#!/usr/bin/env python3
"""Keccak-f[1600] in Tapleaf 0xC2 Script, checked against hashlib and measured with bitcoin-util evalscript.

Representation: five 80-byte rows on the stack (row 0 deepest). Row y holds lanes x = 0..4 as 16-byte
slots, each lane twice (lane || lane, little-endian). Bitwise steps keep the doubled form, and the
rotation of lane x by r is one shift of its row: (row >> 128x + 64 - r) has the rotated lane in its low
8 bytes. See README.md for why this beats 25 lane items and one 200-byte number.

    python3 keccak.py       # checks, measures, writes build/keccak.json
"""
from __future__ import annotations

import hashlib
import json
import os
import random
from pathlib import Path

from gsrasm import Program, evalscript, hx, required_wu

HERE = Path(__file__).resolve().parent
RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
      0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
      0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
M64 = (1 << 64) - 1


# ---- reference ----

def rot(v: int, r: int) -> int:
    return ((v << r) | (v >> (64 - r))) & M64 if r else v


def keccak_f(a: list[int], rounds: int = 24) -> list[int]:
    """Keccak-f[1600] on 25 lanes, lane (x, y) at index x + 5y."""
    a = list(a)
    for rnd in range(rounds):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rot(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rot(a[x + 5 * y], RHO[x][y])
        a = [b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= RC[rnd]
    return a


def to_lanes(state: bytes) -> list[int]:
    return [int.from_bytes(state[8 * i:8 * i + 8], "little") for i in range(25)]


def to_bytes(lanes: list[int]) -> bytes:
    return b"".join(v.to_bytes(8, "little") for v in lanes)


def sponge(msg: bytes, rate: int, pad: int, out_len: int, perm=None) -> bytes:
    """SHA-3 / SHAKE sponge over a byte-state permutation (the reference unless `perm` is given)."""
    perm = perm or (lambda s: to_bytes(keccak_f(to_lanes(s))))
    p = bytearray(msg) + bytes([pad]) + bytes((-len(msg) - 1) % rate)
    p[-1] |= 0x80
    s = bytes(200)
    for i in range(0, len(p), rate):
        s = perm(bytes(a ^ b for a, b in zip(s, bytes(p[i:i + rate]) + bytes(200 - rate))))
    out = b""
    while True:
        out += s[:rate]
        if len(out) >= out_len:
            return out[:out_len]
        s = perm(s)


def rows(lanes: list[int]) -> list[bytes]:
    """The five doubled rows of a state."""
    return [b"".join(lanes[x + 5 * y].to_bytes(8, "little") * 2 for x in range(5)) for y in range(5)]


def unrows(rs: list[bytes]) -> list[int]:
    lanes = [0] * 25
    for y, r in enumerate(rs):
        r = r.ljust(80, b"\0")
        for x in range(5):
            lo, hi = r[16 * x:16 * x + 8], r[16 * x + 8:16 * x + 16]
            assert lo == hi, "a lane lost its doubled form"
            lanes[x + 5 * y] = int.from_bytes(lo, "little")
    return lanes


# ---- script ----

def fetch(depth: int, consume: bool) -> str:
    """Copy (or move) the value at `depth` to the top, with the cheapest opcode."""
    if consume:
        return {0: "", 1: "SWAP", 2: "ROT"}.get(depth, f"{depth} ROLL")
    return {0: "DUP", 1: "OVER"}.get(depth, f"{depth} PICK")


def program(rounds: int = 24) -> Program:
    """[R0 R1 R2 R3 R4] -> [R0' .. R4']: `rounds` rounds of Keccak-f[1600]."""
    p = Program()
    low_halves = hx((b"\xff" * 8 + bytes(8)) * 5)
    double = hx((1 + (1 << 64)).to_bytes(9, "little"))   # x * (1 + 2^64) = x || x for a 64-bit x
    # theta. C = R0 ^ .. ^ R4 (doubled). From CC = C || C: C[x-1] is CC >> 512 and rotl1(C[x+1]) is the low
    # half of CC >> 191; their XOR, masked to the low halves and multiplied by 1 + 2^64, is D doubled (at most
    # 80 bytes). Each row is then XORed with D: rows R4..R1 park on the altstack, R0 consumes D.
    p.macro("THETA", f"""
        DUP 2 PICK XOR 3 PICK XOR 4 PICK XOR 5 PICK XOR
        DUP CAT DUP 512 RSHIFT SWAP 191 RSHIFT XOR {low_halves} AND {double} MUL
        TUCK XOR TOALTSTACK  TUCK XOR TOALTSTACK  TUCK XOR TOALTSTACK  TUCK XOR TOALTSTACK  XOR
        FROMALTSTACK FROMALTSTACK FROMALTSTACK FROMALTSTACK""")
    # rho and pi. Output row y' slot x' = rotl(A[x][y], r) with y = x' and y' = 2x + 3y: a shift of row y and
    # its low 8 bytes, doubled again. A row is copied for its lanes of output rows 0..3 and moved by the last.
    out, stack = [], [f"R{y}" for y in range(5)]       # simulated stack, top last
    for y_out in range(5):
        for x_out in range(5):
            y = x_out
            x = next(x for x in range(5) if (2 * x + 3 * y) % 5 == y_out)
            depth = len(stack) - 1 - stack.index(f"R{y}")
            last = y_out == 4
            if last:
                stack.remove(f"R{y}")
            stack.append("lane")
            shift = 128 * x + 64 - RHO[x][y]
            if shift == 64:
                cut = "8 LEFT"                               # rotation by 0: the lane is the low half of slot 0
            elif shift % 8 == 0:
                cut = f"{shift // 8} 8 SUBSTR"
            else:
                cut = f"{shift} RSHIFT 8 LEFT"
            out.append(f"{fetch(depth, last)} {cut} DUP CAT" + (" CAT" if x_out else ""))
            if x_out:
                stack[-2:] = ["acc"]
        stack[-1] = f"O{y_out}"
    assert stack == [f"O{y}" for y in range(5)], stack
    p.macro("RHOPI", " ".join(out))
    # chi on the top row O: O ^ (~B1 & B2), with B1 and B2 the row turned by one and two lanes, read from O || O
    p.macro("CHI", "DUP DUP CAT DUP 128 RSHIFT INVERT SWAP 256 RSHIFT AND XOR 80 LEFT")
    # one round up to iota: rows O4..O1 park on the altstack after chi, O0 stays on top for iota
    p.macro("ROUND", "@THETA @RHOPI " + "@CHI TOALTSTACK " * 4 + "@CHI")
    p.set_main(" ".join(f"@ROUND {hx(RC[r].to_bytes(8, 'little') * 2)} XOR"
                        " FROMALTSTACK FROMALTSTACK FROMALTSTACK FROMALTSTACK" for r in range(rounds)))
    return p


def with_check(p: Program, want: list[bytes]) -> Program:
    q = Program()
    q.macros, q.main = p.macros, list(p.main)
    q.main += [t for i in range(4) for t in (hx(want[4 - i]), "EQUALVERIFY")] + [hx(want[0]), "EQUAL"]
    return q


def run_perm(p: Program, state: bytes) -> tuple[bytes, int]:
    """Run the permutation script; return the output state read from the final stack and the varops."""
    r = evalscript(p.assemble(), rows(to_lanes(state)))
    rs = [bytes.fromhex(h) for h in r["stack-after"]]
    assert len(rs) == 5, r["error"]
    return to_bytes(unrows(rs)), r["varops"]


def main() -> None:
    # the reference against hashlib
    rng = random.Random(1)
    for n in (0, 3, 135, 136, 137, 500):
        m = rng.randbytes(n)
        assert sponge(m, 136, 0x06, 32) == hashlib.sha3_256(m).digest()
        assert sponge(m, 136, 0x1F, 300) == hashlib.shake_256(m).digest(300)
    p24 = program()
    script_perm = lambda s: run_perm(p24, s)[0]   # noqa: E731

    # the script as the permutation of hashlib's sponges: SHA3-256 and SHAKE256 with a multi-block squeeze
    for m in (b"", b"abc", rng.randbytes(100)):
        assert sponge(m, 136, 0x06, 32, script_perm) == hashlib.sha3_256(m).digest()
    m = rng.randbytes(40)
    assert sponge(m, 136, 0x1F, 272, script_perm) == hashlib.shake_256(m).digest(272)   # 2 squeeze blocks

    # pass/fail with in-script comparison: a correct input passes, a one-bit mutation is rejected
    state = rng.randbytes(200)
    want = rows(keccak_f(to_lanes(state)))
    good = evalscript(with_check(p24, want).assemble(), rows(to_lanes(state)))
    assert good["success"], good["error"]
    bad_state = bytearray(state)
    bad_state[77] ^= 0x10
    bad = evalscript(with_check(p24, want).assemble(), rows(to_lanes(bytes(bad_state))))
    assert not bad["success"]
    # all-ones and all-zero lanes (edge cases for rotations and trimmed numbers)
    for s in (bytes(200), b"\xff" * 200, bytes(8) * 12 + b"\xff" * 104):
        assert run_perm(p24, s)[0] == to_bytes(keccak_f(to_lanes(s)))
    print("matches hashlib.sha3_256 / shake_256 through the sponge; mutated input rejected")

    # cost
    _, v24 = run_perm(p24, state)
    inline = program()
    inline_bytes = len(inline.assemble(inline=True))
    v_inline = evalscript(inline.assemble(inline=True), rows(to_lanes(state)))["varops"]
    macro_bytes = len(p24.assemble())
    _, v1 = run_perm(program(1), state)
    steps = {}
    for name in ("THETA", "RHOPI"):
        q = Program()
        q.macros = {name: p24.macros[name]}
        q.set_main(f"@{name}")
        steps[name] = evalscript(q.assemble(inline=True), rows(to_lanes(state)))["varops"]
    q = Program()
    q.macros = {"CHI": p24.macros["CHI"]}
    q.set_main("@CHI")
    steps["CHI (one row)"] = evalscript(q.assemble(inline=True), rows(to_lanes(state)))["varops"]
    res = {
        "varops_per_permutation_macros": v24,
        "varops_per_permutation_inline": v_inline,
        "unroll_charge": v24 - v_inline,
        "script_bytes_macros": macro_bytes,
        "script_bytes_inline": inline_bytes,
        "required_wu_macros": required_wu(v24),
        "required_wu_inline_budget_only": required_wu(v_inline),
        "one_round_macros": v1,
        "steps_inline": steps,
    }
    (HERE / "build").mkdir(exist_ok=True)
    (HERE / "build" / "keccak.json").write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
