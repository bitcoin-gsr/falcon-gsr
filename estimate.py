#!/usr/bin/env python3
"""Representation micro-costs, and SHAKE256 / Falcon-512 estimates from measured unit costs.

Every unit below is a snippet run inline with `bitcoin-util evalscript`; code that would live in macros
also pays the unroll charge of 300 varops per substituted instruction, added as `+ 300 x instructions`.

    python3 estimate.py     # needs build/keccak.json from keccak.py; writes build/estimate.json
"""
from __future__ import annotations

import json
import random
from pathlib import Path

from gsrasm import cost, le, required_wu, tokens

HERE = Path(__file__).resolve().parent
rng = random.Random(7)
rb = rng.randbytes
SUBST = 300
Q = 12289


def delta(snippet: str, stack: list[bytes]) -> int:
    """Measured varops of `snippet` plus its substitution charge (the run may end in an error state;
    evalscript still reports what was charged)."""
    return cost(snippet, stack) + SUBST * len(tokens(snippet))


def main() -> None:
    k = json.loads((HERE / "build" / "keccak.json").read_text())
    perm = k["varops_per_permutation_macros"]
    u: dict[str, int] = {}

    # ---- representation: the same bitwise work at three granularities ----
    u["xor_8B"] = cost("XOR", [rb(8), rb(8)])
    u["xor_80B"] = cost("XOR", [rb(80), rb(80)])
    u["xor_200B"] = cost("XOR", [rb(200), rb(200)])
    u["pick_8B_depth10"] = cost("10 PICK", [rb(8)] * 12)
    u["rotate_lane_item"] = cost("DUP CAT 37 RSHIFT 8 LEFT", [rb(8)])          # rotl(x, 27) on an 8-byte item
    u["rotate_from_row"] = cost("DUP 293 RSHIFT 8 LEFT DUP CAT", [rb(80)])      # one rho lane from a doubled row
    u["extract_from_200B"] = cost("DUP 96 8 SUBSTR", [rb(200)])                 # one lane out of a 200-byte state

    # ---- Falcon units (2-byte coefficients mod q, as stack items) ----
    a, b = (rng.randrange(Q).to_bytes(2, "little") for _ in range(2))
    w = rng.randrange(1, Q)
    # Cooley-Tukey butterfly, reduced every time: [a b] -> [a + wb, a - wb] mod q
    bfly = f"{le(w)} MUL {Q} MOD 2DUP ADD {Q} MOD ROT ROT {Q} ADD SWAP SUB {Q} MOD"
    u["butterfly_arith"] = delta(bfly, [a, b])
    # moving its operands: a ROLL at the mean NTT stride (511/9 ~ 57), two to and from the altstack
    u["butterfly_moves"] = delta("57 ROLL TOALTSTACK TOALTSTACK FROMALTSTACK FROMALTSTACK", [rb(2)] * 60)
    u["mulmod"] = delta(f"MUL {Q} MOD", [a, b])                          # pointwise product with h (NTT form)
    # s1 = c - t mod q, centred, squared, added to the norm: [norm c t] -> [norm']
    u["norm_coeff"] = delta(f"{Q} SWAP SUB ADD {Q} MOD DUP 6145 LESSTHAN NOTIF {Q} SWAP SUB ENDIF DUP MUL ADD",
                            [rb(3), a, b])
    # hash-to-point sample: [bytes] -> [rest coeff?]: 2 bytes off the front, accept below 5q, reduce
    u["sample"] = delta(f"DUP 2 LEFT SWAP 16 RSHIFT SWAP DUP 61445 LESSTHAN IF {Q} MOD ELSE DROP ENDIF",
                        [rb(136)])
    # unpacking a squeezed lane pair from the doubled rows into bytes: one 8-byte lane per 16-byte slot
    u["squeeze_lane"] = delta("DUP 8 LEFT ROT SWAP CAT SWAP 16 RIGHT", [rb(64), rb(80)])
    u["kronecker_mul_2560"] = cost("MUL", [rb(2560), rb(2560)])

    # ---- SHAKE256 hash-to-point: SHAKE256(nonce(40) || msg(32)) squeezed into 512 values below q ----
    rate = 136
    samples = 546                                 # expected 16-bit samples for 512 accepted (p = 61445/65536)
    blocks = 9                                    # 8 blocks (544 samples) suffice ~36% of the time; 9 almost always
    absorb = 25 * u["squeeze_lane"]               # message block into doubled lanes, about as costly as unpacking
    shake = blocks * perm + absorb + blocks * 17 * u["squeeze_lane"] + samples * u["sample"]

    # ---- Falcon-512 verify, NTT route: s1 = c - s2*h mod (q, x^512 + 1), ||(s1, s2)||^2 <= beta^2 ----
    n, layers = 512, 9
    bflies = n // 2 * layers
    ntt = bflies * (u["butterfly_arith"] + u["butterfly_moves"])
    falcon_ntt = (2 * ntt                         # forward NTT of s2, inverse NTT of the product (h is in NTT form)
                  + n * u["mulmod"]               # pointwise product
                  + n * u["mulmod"]               # scaling by n^-1 after the inverse NTT
                  + 2 * n * u["norm_coeff"])      # s1 and s2 coefficients into the norm
    # Kronecker route: s2*h as one big MUL of 512 five-byte slots (2560 bytes each), then per-coefficient work
    falcon_kron = u["kronecker_mul_2560"] + 3 * n * u["norm_coeff"]

    res = {
        "units": u,
        "keccak_f": perm,
        "shake256_hash_to_point": {"permutations": blocks, "varops": shake, "wu": required_wu(shake)},
        "falcon512_ntt": {"butterflies": 2 * bflies, "ntt_varops": 2 * ntt, "arith_varops": falcon_ntt,
                          "total_varops": falcon_ntt + shake, "wu": required_wu(falcon_ntt + shake)},
        "falcon512_kronecker": {"arith_varops": falcon_kron, "total_varops": falcon_kron + shake,
                                "wu": required_wu(falcon_kron + shake)},
    }
    (HERE / "build" / "estimate.json").write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
