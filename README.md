# Keccak-f[1600] in GSR Tapleaf 0xC2 Script

Keccak-f[1600] (24 rounds) runs in 13.56M varops per permutation with macros, so it needs 1,407 WU of budget. The script is 1,008 bytes. A Falcon-512 verifier looks like a realistic demo at about 18k WU if the ring product uses one Kronecker `MUL`, or about 34k WU with a textbook NTT. SHAKE256 alone costs about 13.6k WU.

Measured on jmoik/bitcoin `gsr` @ ad6c16f (`bitcoin-util evalscript`, from `gsr-stark-verifier/build`).

## Representation

The state is five 80-byte rows. Row y holds lanes x = 0..4 as 16-byte slots, and each slot holds its lane twice (lane || lane). Rotating lane x by r is then one shift of its row: the low 8 bytes of `row >> (128x + 64 - r)`. θ and χ act on whole rows.

The two layouts in the brief both lose to this one (units from `estimate.py`; a measurement that leaves one item includes about 366 varops for reading it at the end):

- 25 lane items. Every bitwise op pays its fixed charges per lane: an 8-byte XOR costs 1,622 varops, against 3,350 for all 200 bytes at once. Each operand fetch is a PICK (2,678), and θ and χ need about 75 fetches per round.
- One 200-byte number. θ and χ are cheap, but ρ needs a different rotation per lane and π a different move per lane. Per lane, cutting the lane out costs 6,068 and rotating the cut lane costs 7,008. The prototype estimate was about 620k per round, against 566k measured here.
- Doubled rows. Copying a row, shifting it and re-doubling the lane costs 8,622, about the same as the cut alone in the 200-byte form. Bitwise ops work on 80 bytes at a time.

This is the representation of `shrincs-gsr/gsr/keccak.py`, which measures 14,425,040 varops on the same build. This version saves 6% in θ, χ and ρπ:

- D is doubled by one `MUL` by 1 + 2^64 instead of `DUP 64 LSHIFT OR 80 LEFT`.
- Each row is XORed with D by `TUCK XOR TOALTSTACK` instead of `4 ROLL` plus an altstack copy of D.
- χ parks finished rows on the altstack instead of rolling the next row up.
- Byte-aligned shifts use `SUBSTR`, and lane (0,0) is not shifted.

## Cost (`keccak.py`, written to `build/keccak.json`)

| | varops | script bytes | WU needed |
|---|---|---|---|
| with macros (THETA, RHOPI, CHI, ROUND) | 13,560,872 | 1,008 | 1,407 |
| of which unroll charge | 2,533,472 | | |
| inline, no macros | 11,027,400 | 12,096 | 12,096 (its own bytes) |

WU needed = ceil((varops + 500,000) / 10,000). The inline script costs about 9 times more weight than its varops need, so macros win even though every substituted instruction pays 300 varops.

One round costs 566k with macros. Measured inline, without the unroll charge, θ is 68.8k, ρπ is 272.2k and χ is 5 × 22.3k. ρπ is half the round: each lane is a row copy, a shift, a cut and a re-doubling.

## Checks

- The Python reference matches `hashlib.sha3_256` and `hashlib.shake_256` for messages of 0 to 500 bytes.
- The Script permutation, used as the permutation of a Python sponge, reproduces `sha3_256("")`, `sha3_256("abc")`, a 100-byte message and a two-block SHAKE256 squeeze (272 bytes).
- With an in-script comparison against the expected rows, the correct input passes and an input with one bit flipped is rejected.
- All-zero and all-one states, and a state with zero low lanes, match the reference. The all-zero state covers values that trim to nothing.

## SHAKE256 and Falcon-512 (`estimate.py`, written to `build/estimate.json`)

Code that would sit in macros is priced with its 300-per-instruction unroll charge.

Hash-to-point is SHAKE256(nonce ‖ message) squeezed into 16-bit samples. A sample is accepted when it is below 5q = 61445, which happens with probability 0.938. 512 coefficients need about 546 samples, or 1,092 bytes. That is 9 blocks of 136 bytes, so 9 permutations: 8 suffice in only about 41% of cases, and a script cannot loop. The cost is 9 × 13.56M plus absorbing, unpacking and sampling (21k per sample), about 136M varops or 13.6k WU.

Verification computes s1 = c − s2·h mod (q, x^512 + 1) and checks ‖(s1, s2)‖² ≤ β². h is stored in NTT form as script constants. Measured units:

- Butterfly: 29.4k, as MUL by twiddle, MOD, ADD and SUB on 2-byte values, reduced every time.
- Operand moves: 7.2k, a ROLL at the mean stride plus altstack traffic.
- MUL + MOD: 7.6k.
- Norm step: 24.9k per coefficient.

The two routes for the ring product:

| | arithmetic | + SHAKE256 | WU needed |
|---|---|---|---|
| NTT: 2 × 2,304 butterflies, pointwise products, norm | 202M | 338M | about 33.8k |
| Kronecker: one 2560 × 2560-byte `MUL` (6.66M), then per-coefficient reduction and norm | 45M | 181M | about 18.1k |

The Kronecker figure prices the per-coefficient work as 3 × 512 norm-sized steps, and the NTT figure keeps every value reduced. Both are rough, within perhaps ±30%. They match the earlier `shrincs-gsr/gsr/estimates.py` figure (186M) because the Kronecker route is the same.

## Verdict

A Falcon-512 verifier is a realistic demo at roughly 18–20k WU, about 5 kvB. That is far below the 400k WU standard limit. SHAKE256 is about three quarters of it: 9 permutations at 1.36k WU each.

The open costs are the ones a real build would settle:

- s2 must be supplied uncompressed (1,024 bytes). Parsing Falcon's compressed encoding bit by bit in Script would cost more.
- The 9-block squeeze is fixed, so about 1 in 10^18 signatures would need a fresh nonce.
- A cheaper ρπ would help everything Keccak-based, Ethereum-style proofs included. ρπ is 272k of each 566k round.

## Files

- `keccak.py`: the reference, the Script generator, the checks and the measurement.
- `estimate.py`: the representation units, SHAKE256 and Falcon-512.
- `gsrasm.py`: the token assembler with macros and the `evalscript` runner. It uses `gsr-stark-verifier/risc0-succinct/tools/gsr.py` for minimal pushes.

```
python3 keccak.py && python3 estimate.py
```
