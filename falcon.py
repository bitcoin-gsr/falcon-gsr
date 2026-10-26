#!/usr/bin/env python3
"""A Falcon-512 (FN-DSA) verifier in Tapleaf 0xC2 Script, checked against falcon_ref.py and measured with
bitcoin-util evalscript.

Witness (bottom to top): msg (32 bytes), nonce (40 bytes), s2 (1,024 bytes: e_i = s2_i + 6144 as 2-byte
little-endian numbers). The public key h is a script constant. The script leaves 1 if
||(s1, s2)||^2 <= beta^2 for s1 = c - s2 h mod (q, x^512 + 1) and c = HashToPoint(nonce || msg).
With `bound=True` (spend.py), msg is not a witness item: OP_TX rebuilds it from the spending transaction.

Stages, in script order:

1. s2. The witness s2 is cut into groups of 8. Each coefficient e adds e * (2^(64+40j) + 12288 - e) to a
   group number Ep, which puts e in a 5-byte slot of the Kronecker operand E and adds w = e (12288 - e) =
   6144^2 - s2^2 to a 64-bit norm sum below the slots. A sentinel bit keeps Ep at 49 bytes, so the slots are
   cut out as exactly 40 bytes and concatenated into E (2,560 bytes); the norm sum carries to the next group.
2. Ring product. P = E * H is one MUL of two 2,560-byte numbers (H: h_j in 5-byte slots). With LO and HI
   the low and high 512 slots of P, V = HI + M - LO has V_i = -(s2 h)_i + 6144 mod q in slot i. M is a
   constant: per slot, at least the largest LO_i, and congruent to the offset terms (6144 in e, 6144 in V).
3. Hash to point. SHAKE256(nonce || msg) runs as 9 Keccak-f[1600] permutations of keccak.py. After each,
   rows 0..3 (lanes 0..16 = 136 bytes) are byte-reversed with a leading 0x01 byte, so every big-endian
   16-bit sample is a 2-byte SUBSTR at a fixed offset, and parked on the altstack. The rows are then
   processed from the last sample back to the first: each sample below 5q goes to the altstack. The first
   accepted sample (c_0) ends on top; samples beyond the 512th end below c_511 and stay there. Fewer than
   512 accepted samples empty the altstack, and the script fails.
4. s1 and the norm. For i = 0..511: r = (c_i + V_i) mod q is s1_i + 6144 with s1_i centred, and
   w = r (12288 - r) = 6144^2 - s1_i^2 is added to the norm sum. The script checks
   sum(w) >= 1024 * 6144^2 - beta^2, which is ||(s1, s2)||^2 <= beta^2.

A Bitcoin-specific variant replaces stage 3 (`htp=SHA`): the stream is the BIP 340 tagged SHA-256 hashes of
nonce || msg || i for a 1-byte i = 38 .. 0, last first, 16 samples each (falcon_ref.hash_to_point_sha256).
Stock FN-DSA signers cannot sign for it. Its spend is bound by its weight rather than its budget, so it keeps h
as 896 bytes of 14-bit fields and builds H and M in the script: M = m U for one m, because E gets 6145 more per
slot (s2 + q instead of s2 + 6144), which makes every slot's offset the same.

    python3 falcon.py       # tests, measures, writes build/falcon.json
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import time
from pathlib import Path

import falcon_ref as ref
import gsrasm
import keccak
from gsrasm import Program, evalscript, hx, required_wu

HERE = Path(__file__).resolve().parent
gsrasm.OPS.update({"GREATERTHAN": 0xA0, "1SUB": 0x8C})

N, Q = ref.N, ref.Q
HALF = 6144                       # (q - 1) / 2: offset of e and of r
SLOT = 40                         # Kronecker slot, bits
EMAX = 65535                      # e is any 2-byte value; out-of-range s2 only fails the norm
W_BIAS = 1 << 63                  # keeps the norm sum of a group number nonnegative
SENTINEL = 1 << 384               # keeps a group number at 49 bytes: 8-byte sum, 40-byte slots, 1
BLOCKS = 9                        # SHAKE256 blocks (Keccak permutations)
SHAKE, SHA = "shake256", "sha256"  # HashToPoint: FN-DSA's, or the tagged SHA-256 variant of falcon_ref
CALLS = ref.SHA_CALLS             # SHA-256 calls of the variant, 16 samples each
# OP_TX selector of shrincs-gsr's stage 5: COLLATE version, locktime, input and output counts; all inputs'
# outpoint, amount, scriptPubKey and sequence; all outputs; the input index, annex and tapleaf hash.
# A bound verifier signs SHA256 of the collated bytes.
OPTX_SELECTOR = bytes([0x00, 0x57, 0x0B, 0x22, 0x2F, 0x03])
H_BITS = 14                       # the variant's h: 14 bits per coefficient, spread to slots in groups of 16


# ---- constants ----

def negacyclic(a: list[int], b: list[int]) -> list[int]:
    out = [0] * N
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                k = i + j
                if k < N:
                    out[k] += x * y
                else:
                    out[k - N] -= x * y
    return out


def pack(values: list[int], bits: int = SLOT) -> int:
    return sum(v << (bits * i) for i, v in enumerate(values))


def h_constants(h: list[int]) -> tuple[int, int]:
    """H (h in 5-byte slots) and M. With P = E * H for e = s2 + 6144, slot i of HI + M - LO must be
    -(s2 h)_i + 6144 mod q: -(s2 h)_i = HI_i - LO_i + 6144 (u h)_i for u = 1 + x + .. + x^511."""
    uh = negacyclic([1] * N, h)
    M = []
    for i in range(N):
        low = (i + 1) * EMAX * (Q - 1)               # largest LO_i
        want = HALF * (uh[i] + 1) % Q
        M.append(low + (want - low) % Q)
    return pack(h), pack(M)


def compact_constants(h: list[int]) -> tuple[bytes, int]:
    """The SHA-256 variant's constants, small because its spend is bound by its weight: h packed in 14-bit
    fields (896 bytes), and m. With e' = e + 6145 = s2 + q, (e' h) = (s2 h) mod q, so every slot of M needs the
    same residue 6144 and M = m U for U = 1 + 2^40 + .. + 2^(40 * 511)."""
    low = N * (EMAX + Q - HALF) * (Q - 1)            # largest LO_i for any slot
    return pack(h, H_BITS).to_bytes(N * H_BITS // 8, "little"), low + (HALF - low) % Q


def k_min(beta2: int) -> int:
    """sum(w) >= k_min  <=>  1024 * 6144^2 - sum(w) = ||(s1, s2)||^2 <= beta2."""
    return 2 * N * HALF * HALF - beta2


# ---- a model of what the script computes ----

def accepted_samples(nonce: bytes, msg: bytes, htp: str = SHAKE, blocks: int = BLOCKS, calls: int = CALLS) -> list[int]:
    """The samples below 5q of the whole stream the script reads: `blocks` SHAKE256 blocks (the Python Keccak of
    keccak.py) or `calls` tagged SHA-256 hashes."""
    if htp == SHAKE:
        out = keccak.sponge(nonce + msg, 136, 0x1F, 136 * blocks)
    else:
        out = b"".join(ref.tagged_hash(ref.SHA_TAG, nonce + msg + bytes([i])) for i in range(calls))
    ts = [(out[2 * i] << 8) | out[2 * i + 1] for i in range(len(out) // 2)]
    return [t for t in ts if t < 5 * Q]


def model(h: list[int], nonce: bytes, msg: bytes, s2: list[int], htp: str = SHAKE, **kw) -> dict:
    e = [x + HALF for x in s2]
    if htp == SHAKE:
        H, M = h_constants(h)
        P = pack(e) * H
    else:
        M = compact_constants(h)[1] * pack([1] * N)
        P = pack([x + Q - HALF for x in e]) * pack(h)
    lo, hi = P % (1 << (SLOT * N)), P >> (SLOT * N)
    V = hi + M - lo
    ts = accepted_samples(nonce, msg, htp, **kw)[:N]
    r = [(t + ((V >> (SLOT * i)) & ((1 << SLOT) - 1))) % Q for i, t in enumerate(ts)]
    w = W_BIAS + sum(x * (2 * HALF - x) for x in e) + sum(x * (2 * HALF - x) for x in r)
    return {"r": r, "acc": w}


# ---- script ----

def group_s2() -> str:
    """[chunk Ep] -> [Ep']: 8 coefficients of a 16-byte chunk into a group number, then its 40 slot bytes
    onto the altstack piece and its norm sum into the next group number."""
    body = []
    for j in range(8):
        d = (1 << (64 + SLOT * j)) + 2 * HALF
        cut = "OVER 2 LEFT" if j == 0 else f"OVER {2 * j} 2 SUBSTR"
        body.append(f"{cut} {d} OVER SUB MUL ADD")
    body.append(f"NIP DUP 8 LEFT {SENTINEL} ADD SWAP 8 40 SUBSTR FROMALTSTACK SWAP CAT TOALTSTACK")
    return " ".join(body)


def sub_s2() -> str:
    """[sub Ep] -> [Ep' piece]: 64 coefficients (a 128-byte cut) into a 320-byte piece of E."""
    return "0 TOALTSTACK " + " ".join(f"OVER {16 * g} 16 SUBSTR SWAP @GROUP_S2" for g in range(8)) \
        + " NIP FROMALTSTACK"


def group_s1() -> str:
    """[chunk acc] -> [acc']: 8 slots of V, each with c_i from the altstack, into the norm sum."""
    body = []
    for j in range(8):
        cut = "OVER 5 LEFT" if j == 0 else f"OVER {5 * j} 5 SUBSTR"
        body.append(f"{cut} FROMALTSTACK ADD {Q} MOD {2 * HALF} OVER SUB MUL ADD")
    return " ".join(body) + " NIP"


def sub_s1() -> str:
    """[sub acc] -> [acc']: 64 slots (a 320-byte cut of V)."""
    return " ".join(f"OVER {40 * g} 40 SUBSTR SWAP @GROUP_S1" for g in range(8)) + " NIP"


ACCEPT = f"DUP TOALTSTACK {5 * Q} LESSTHAN NOTIF FROMALTSTACK DROP ENDIF"


def take_samples(offs: list[int]) -> str:
    """[R'] -> []: the 2-byte samples of a byte-reversed value at these offsets, in this order; accepted ones
    onto the altstack. The last one consumes R'."""
    return " ".join(("" if i == len(offs) - 1 else "DUP ") + f"{o} 2 SUBSTR {ACCEPT}" for i, o in enumerate(offs))


def row_samples(lanes: int, last: int) -> str:
    """The samples of a reversed row, last first. Sample k of lane x starts at `last - 16x - 2k`."""
    return take_samples([last - 16 * x - 2 * k for x in reversed(range(lanes)) for k in reversed(range(4))])


def spread() -> str:
    """[chunk] -> []: 16 coefficients of h from 14-bit fields into 5-byte slots, appended to the altstack piece.
    Level j moves the fields whose index has bit j set up by 26 * 2^j; its mask keeps the others."""
    body = []
    for j in reversed(range(4)):
        mask = sum(((1 << (H_BITS << j)) - 1) << (SLOT * b << (j + 1)) for b in range(16 >> (j + 1)))
        body.append(f"DUP {mask} AND TUCK SUB {(SLOT - H_BITS) << j} LSHIFT ADD")
    body.append(f"{1 << 640} ADD 80 LEFT FROMALTSTACK SWAP CAT TOALTSTACK")
    return " ".join(body)


def double_lanes(count: int) -> str:
    """[bytes] -> [row]: `count` 8-byte lanes, each doubled (lane || lane), concatenated."""
    parts = ["DUP 8 LEFT DUP CAT"]
    parts += [f"OVER {8 * x} 8 SUBSTR DUP CAT CAT" for x in range(1, count - 1)]
    parts.append(f"SWAP {8 * (count - 1)} 8 SUBSTR DUP CAT CAT")
    return " ".join(parts)


def stages(h: list[int], htp: str = SHAKE, blocks: int = BLOCKS, calls: int = CALLS, beta2: int = ref.BETA2,
           final: bool = True) -> list[tuple[str, str]]:
    """The main script as named stages. `final=False` ends with the norm sum and a 0 (a failing stack that
    evalscript reports) instead of the comparison."""
    if htp == SHAKE:
        H, M = h_constants(h)
        # [E W'] -> [W' V], V = HI + M - LO for P = E * H
        product = (f"SWAP {hx(H.to_bytes(SLOT * N // 8, 'little').rstrip(bytes(1)))} MUL "
                   f"DUP {SLOT * N // 8} LEFT SWAP {SLOT * N} RSHIFT "
                   f"{hx(M.to_bytes(SLOT * N // 8, 'little').rstrip(bytes(1)))} ADD SWAP SUB")
    else:
        hblob, m = compact_constants(h)
        groups = len(hblob) // 28
        # [E W'] -> [W' V]: H from 32 groups of 16 fields, U = (2^20480 - 1) / (2^40 - 1), E' = E + 6145 U,
        # P = E' * H, V = HI + m U - LO
        product = (f"SWAP {hx(hblob.rstrip(bytes(1)))} 0 TOALTSTACK "
                   + " ".join(f"DUP {28 * g} 28 SUBSTR @SPREAD" for g in range(groups - 1))
                   + f" {28 * (groups - 1)} 28 SUBSTR @SPREAD FROMALTSTACK "
                   f"1 {SLOT * N} LSHIFT 1SUB {(1 << SLOT) - 1} DIV "
                   f"ROT OVER {Q - HALF} MUL ADD ROT MUL "
                   f"DUP {SLOT * N // 8} LEFT SWAP {SLOT * N} RSHIFT ROT {m} MUL ADD SWAP SUB")
    st = [
        # [msg nonce s2] -> [msg nonce E W']: the pieces of E concatenate below the group number
        ("s2", "SIZE 1024 NUMEQUALVERIFY "
               f"0 {SENTINEL + W_BIAS} "
               + " ".join(f"2 PICK {128 * s} 128 SUBSTR SWAP @SUB_S2 ROT SWAP CAT SWAP" for s in range(8))
               + " ROT DROP 8 LEFT"),
        ("product", product),
    ]
    if htp == SHAKE:
        rows = 4 * blocks
        # the padded block nonce || msg || 0x1F .. 0x80: row 1 ends with lane 9 = 0x1F, row 3 holds lane 16
        lane9 = hx((0x1F).to_bytes(8, "little") * 2)
        row3 = hx(bytes(16) + (0x80 << 56).to_bytes(8, "little") * 2)
        st += [
            # [msg nonce W' V] -> [W' V R0 R1 R2 R3 R4]
            ("absorb", "3 ROLL 3 ROLL SIZE 40 NUMEQUALVERIFY " + double_lanes(5)
                       + " SWAP SIZE 32 NUMEQUALVERIFY " + double_lanes(4) + f" {lane9} CAT 0 {row3} 0"),
            ("keccak", " ".join(["@PERM @SQUEEZE"] * blocks)),
            # the rows come back with the first one on top; the last row (row 3 of the last block) is rolled up first
            ("sample", "2DROP 2DROP DROP " + "FROMALTSTACK " * rows
                       + " ".join(f"{rows - 1 - k} ROLL" * (k < rows - 1) + (" @ROW8" if k % 4 == 0 else " @ROW20")
                                  for k in range(rows))),
        ]
    else:
        tag = hashlib.sha256(ref.SHA_TAG).digest()
        st += [
            # [msg nonce W' V] -> [W' V]: the tagged hashes of nonce || msg || i, the last call first, each
            # byte-reversed for its samples
            ("hash", f"3 ROLL 3 ROLL SIZE 40 NUMEQUALVERIFY SWAP SIZE 32 NUMEQUALVERIFY CAT {hx(tag + tag)} SWAP CAT "
                     + " ".join(f"DUP {hx(bytes([i]))} CAT SHA256 BYTEREV @BLOCK16" for i in reversed(range(calls)))
                     + " DROP"),
        ]
    st += [
        # [W' V] -> [bool]: the norm sum continues from W'
        ("s1", "SWAP " + " ".join(f"OVER {320 * s} 320 SUBSTR SWAP @SUB_S1" for s in range(8)) + " NIP"
               + (f" {k_min(beta2) + W_BIAS - 1} GREATERTHAN" if final else " 0")),
    ]
    return st


def program(h: list[int], upto: int | None = None, htp: str = SHAKE, bound: bool = False, padded: bool = False,
            **kw) -> Program:
    """`bound`: the message is not a witness item but OP_TX's SHA256 of the spending transaction
    (OPTX_SELECTOR), so the witness is [nonce s2]. `padded`: one more witness item below the others, which
    only adds weight (and so budget) and is dropped at the end."""
    if htp == SHA:
        p = Program()
        # a reversed digest: sample k (bytes 2k, 2k + 1) is at 30 - 2k
        p.macro("BLOCK16", take_samples([30 - 2 * k for k in reversed(range(16))]))
        p.macro("SPREAD", spread())
    else:
        p = sha3_macros()
    p.macro("GROUP_S2", group_s2())
    p.macro("SUB_S2", sub_s2())
    p.macro("GROUP_S1", group_s1())
    p.macro("SUB_S1", sub_s1())
    st = stages(h, htp=htp, **kw)
    # [nonce s2] -> [msg nonce s2]
    prologue = f"{hx(OPTX_SELECTOR)} TX SHA256 ROT ROT " if bound else ""
    p.set_main(prologue + " ".join(text for _, text in st[:upto]) + (" NIP" if padded else ""))
    return p


def sha3_macros() -> Program:
    p = keccak.program()
    p.macro("PERM", " ".join(p.main))
    # rows 0..3 of the state, each + 2^640 (row 3 cut to lanes 15 and 16, + 2^256) and byte-reversed
    p.macro("SQUEEZE", f"4 PICK {1 << 640} ADD BYTEREV TOALTSTACK 3 PICK {1 << 640} ADD BYTEREV TOALTSTACK "
                       f"2 PICK {1 << 640} ADD BYTEREV TOALTSTACK OVER 32 LEFT {1 << 256} ADD BYTEREV TOALTSTACK")
    p.macro("ROW20", row_samples(5, 79))
    p.macro("ROW8", row_samples(2, 31))
    return p


def witness(nonce: bytes, msg: bytes, s2: list[int]) -> list[bytes]:
    return [msg, nonce, b"".join((x + HALF).to_bytes(2, "little") for x in s2)]


# ---- tests and measurement ----

def run(p: Program, wit: list[bytes]) -> dict:
    return evalscript(p.assemble(), wit)


def p_short(samples: int) -> float:
    """Probability that fewer than 512 of `samples` 16-bit samples are below 5q."""
    p = 5 * Q / 65536
    return sum(math.comb(samples, k) * p ** k * (1 - p) ** (samples - k) for k in range(N))


def check(sk: dict, rng: random.Random, htp: str) -> dict:
    """Tests one HashToPoint variant of the verifier against falcon_ref and measures it."""
    h = sk["h"]
    sign_htp = ref.hash_to_point if htp == SHAKE else ref.hash_to_point_sha256
    print(f"-- {htp}")
    sigs = []
    for i in range(3):
        msg = bytes([i]) * 32
        sig = ref.sign(sk, msg, rng, sign_htp)
        assert ref.verify(h, msg, sig["nonce"], sig["s2"], sign_htp)
        sigs.append((msg, sig))
    # the model reproduces s1 and the norm of the reference
    for msg, sig in sigs:
        m = model(h, sig["nonce"], msg, sig["s2"], htp=htp)
        assert [x - HALF for x in m["r"]] == sig["s1"]
        assert m["acc"] - W_BIAS == 2 * N * HALF * HALF - sum(x * x for x in sig["s1"] + sig["s2"])

    full = program(h, htp=htp)
    script = full.assemble()
    t = time.time()
    results = []
    for msg, sig in sigs:
        r = run(full, witness(sig["nonce"], msg, sig["s2"]))
        assert r["success"], r["error"]
        results.append(r["varops"])
    print(f"{len(sigs)} signatures accepted ({1000 * (time.time() - t) / len(sigs):.0f} ms each), varops {results}")

    # the norm sum in the script equals the model's, exactly (an extra 0 keeps the stack for reading)
    msg, sig = sigs[0]
    r = run(program(h, htp=htp, final=False), witness(sig["nonce"], msg, sig["s2"]))
    acc, want = int.from_bytes(bytes.fromhex(r["stack-after"][-2]), "little"), model(h, sig["nonce"], msg, sig["s2"], htp=htp)
    assert acc == want["acc"], (acc, want["acc"])
    # the bound is inclusive: beta^2 = this signature's norm accepts, one less rejects
    norm = sum(x * x for x in sig["s1"] + sig["s2"])
    assert run(program(h, htp=htp, beta2=norm), witness(sig["nonce"], msg, sig["s2"]))["success"]
    assert not run(program(h, htp=htp, beta2=norm - 1), witness(sig["nonce"], msg, sig["s2"]))["success"]
    print("norm sum matches the model; the bound is exact at norm and norm - 1")

    # rejections: a changed s2 coefficient, message, nonce, a short s2, and signatures that do not belong
    bad = list(sig["s2"])
    bad[100] += 1
    other_htp = ref.hash_to_point_sha256 if htp == SHAKE else ref.hash_to_point
    other = ref.sign(sk, msg, rng, other_htp)
    cases = {
        "s2[100] + 1": witness(sig["nonce"], msg, bad),
        "message": witness(sig["nonce"], bytes([9]) * 32, sig["s2"]),
        "nonce bit": witness(bytes([sig["nonce"][0] ^ 1]) + sig["nonce"][1:], msg, sig["s2"]),
        "s2 short": [msg, sig["nonce"], witness(sig["nonce"], msg, sig["s2"])[2][:-2]],
        "another message's signature": witness(sigs[1][1]["nonce"], msg, sigs[1][1]["s2"]),
        f"a signature with {SHA if htp == SHAKE else SHAKE} HashToPoint": witness(other["nonce"], msg, other["s2"]),
    }
    for name, wit in cases.items():
        r = run(full, wit)
        assert not r["success"], name
        print(f"rejected: {name} ({r['error']})")

    # a fixed stream: with 544 samples (8 blocks or 34 calls), a nonce that needs more fails and one that does not
    # passes
    short = program(h, htp=htp, blocks=8, calls=34)
    seen, varops_short = set(), None
    while len(seen) < 2:
        msg = rng.randbytes(32)
        sig = ref.sign(sk, msg, rng, sign_htp)
        _, used = sign_htp(sig["nonce"], msg)
        fits = used <= 544
        if fits in seen:
            continue
        seen.add(fits)
        r = run(short, witness(sig["nonce"], msg, sig["s2"]))
        assert r["success"] == fits, (used, r["error"])
        print(f"544 samples, 512th accepted at {used}: {'accepted' if fits else 'rejected (' + r['error'] + ')'}")
        if fits:
            varops_short = r["varops"]

    # cost
    msg, sig = sigs[0]
    wit = witness(sig["nonce"], msg, sig["s2"])
    per_stage, prev = {}, 0
    for k, (name, _) in enumerate(stages(h, htp=htp)):
        v = run(program(h, htp=htp, upto=k + 1), wit)["varops"]
        per_stage[name] = v - prev
        prev = v
    inline = full.assemble(inline=True)
    v_inline = evalscript(inline, wit)["varops"]
    item = lambda b: len(b) + (1 if len(b) < 253 else 3)   # noqa: E731
    wit_bytes = sum(item(x) for x in wit)
    spend_bytes = 1 + wit_bytes + item(script) + item(bytes(33))   # item count, items, script, control block
    # one input and one P2TR output: 94 non-witness bytes (version, counts, outpoint, sequence, output, locktime)
    # at 4 WU, the segwit marker and flag, and the spend's witness
    tx_wu = 4 * 94 + 2 + spend_bytes
    units = {"s2_per_coefficient": per_stage["s2"] // N, "s1_per_coefficient": per_stage["s1"] // N}
    if htp == SHAKE:
        samples = 68 * BLOCKS
        units |= {"per_sample": per_stage["sample"] // samples,
                  "keccak_and_squeeze_per_block": per_stage["keccak"] // BLOCKS}
        stream = {"blocks": BLOCKS, "p_short": p_short(samples), "p_short_8_blocks": p_short(544),
                  "varops_8_blocks": varops_short, "required_wu_8_blocks": required_wu(varops_short)}
    else:
        samples = 16 * CALLS
        units |= {"per_call_with_samples": per_stage["hash"] // CALLS}
        assert ref.hash_to_point_sha256(sig["nonce"], msg, 35)[0] is not None
        alt = program(h, htp=htp, calls=35)
        r35 = run(alt, wit)
        assert r35["success"]
        stream = {"calls": CALLS, "p_short": p_short(samples), "p_short_35_calls": p_short(16 * 35),
                  "varops_35_calls": r35["varops"], "required_wu_35_calls": required_wu(r35["varops"]),
                  "script_bytes_35_calls": len(alt.assemble())}
    vectors = [{"msg": m.hex(), "nonce": s["nonce"].hex(), "s2": s["s2"]} for m, s in sigs]
    return {
        "vectors": vectors,
        "varops": results,
        "varops_by_stage": per_stage,
        "units": units,
        "stream": stream,
        "unroll_charge": results[0] - v_inline,
        "script_bytes": len(script),
        "script_bytes_inline": len(inline),
        "witness_item_bytes": wit_bytes,
        "spend_witness_bytes": spend_bytes,
        "tx_wu_1in_1out": tx_wu,
        "required_wu": required_wu(max(results)),
        "weight_needed": max(tx_wu, required_wu(max(results))),
    }


def main() -> None:
    rng = random.Random(512)
    sk = ref.keygen(rng)
    h = sk["h"]
    assert ref.mul_zq(sk["f"], h) == [x % Q for x in sk["g"]], "h = g / f"
    a, b = [rng.randrange(Q) for _ in range(N)], [rng.randrange(Q) for _ in range(N)]
    assert ref.mul_zq(a, b) == [x % Q for x in negacyclic(a, b)], "NTT product"

    res = {htp: check(sk, rng, htp) for htp in (SHAKE, SHA)}
    vectors = {"h": h} | {htp: r.pop("vectors") for htp, r in res.items()}
    (HERE / "build").mkdir(exist_ok=True)
    (HERE / "build" / "falcon.json").write_text(json.dumps(res, indent=2) + "\n")
    (HERE / "build" / "falcon_vectors.json").write_text(json.dumps(vectors) + "\n")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
