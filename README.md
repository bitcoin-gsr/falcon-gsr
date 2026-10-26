# Keccak-f[1600] and Falcon-512 in GSR Tapleaf 0xC2 Script

Keccak-f[1600] (24 rounds) runs in 13.56M varops per permutation with macros, so it needs 1,407 WU of budget. The script is 1,008 bytes. A complete Falcon-512 verifier built on it (`falcon.py`) runs in 162.4M varops; bound to its transaction by `OP_TX`, a one-input, one-output spend weighs 16,289 WU, against about 18.1k WU estimated. SHAKE256 is 81% of it. A Bitcoin-specific variant that hashes to the point with tagged SHA-256 instead weighs 4,566 WU, 3.6 times less, but stock FN-DSA signers cannot sign for it.

Measured on jmoik/bitcoin `gsr` @ ad6c16f, with `bitcoin-util evalscript` from `gsr-stark-verifier/build` and, for whole spends, Core's `VerifyScript` (`tools/txeval.cpp`).

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

## Falcon-512 verifier (`falcon.py`, written to `build/falcon.json`)

This section measures the verifier with the message as a witness item, which authorizes nothing; the spends bound to their transaction follow below. The witness is the message (32 bytes), the nonce (40 bytes) and s2 uncompressed (1,024 bytes: s2_i + 6144 as 2-byte numbers). The public key h is a script constant. The script leaves 1 when ‖(s1, s2)‖² ≤ β² = 34,034,726, for s1 = c − s2·h mod (q, x^512 + 1) and c = HashToPoint(nonce ‖ msg).

| stage | varops | per unit |
|---|---|---|
| s2: norm terms and the Kronecker operand E | 10,959,771 | 21,405 per coefficient |
| ring product: one 2560 × 2560-byte `MUL` and the fold | 6,850,144 | |
| absorbing nonce ‖ msg into doubled rows | 89,546 | |
| 9 × (Keccak-f[1600] and squeeze) | 122,849,556 | 13,649,950 per block |
| sampling: 612 samples, accepted below 5q | 8,806,740 | 14,390 per sample |
| s1, centring and the norm check | 12,799,542 | 24,999 per coefficient |
| total | 162,355,299 | |

Three signatures measure 162,355,299 to 162,361,435 varops, because the number of accepted samples and the value sizes vary. Of the total, 29.7M is the unroll charge. The worst of the three needs ceil((162,361,435 + 500,000) / 10,000) = 16,287 WU.

| | script bytes | WU needed |
|---|---|---|
| with macros | 8,150 | 16,287 |
| inline, no macros | 158,270 | 158,270 (its own bytes) |

The spend's witness (the three items, the script and the control block) is 9,289 WU, so the transaction must carry about 7,000 WU more weight to fund the budget. Because those bytes are paid for anyway, the script keeps H and M as 2,560-byte constants instead of building them.

How each stage works:

- s2. Each coefficient e of a group of 8 adds e·(2^(64+40j) + 12288 − e) to a group number, in 9 opcodes. That places e in a 5-byte slot of E and adds e(12288 − e) = 6144² − s2² to a 64-bit norm sum below the slots. A sentinel bit keeps the group number at 49 bytes, so its slots are cut out as exactly 40 bytes and concatenated, and the norm sum carries into the next group.
- Ring product. P = E·H in one `MUL`. With LO and HI the low and high 512 slots of P, V = HI + M − LO holds −(s2·h)_i + 6144 mod q in slot i. The constant M exceeds every LO_i in its slot and absorbs both offsets, so the negacyclic fold is one `ADD` and one `SUB` on whole numbers.
- Hash to point. After each permutation, rows 0–3 get a leading byte and are byte-reversed, so every big-endian sample is a 2-byte `SUBSTR` at a fixed offset. The rows wait on the altstack. Then all samples are read from last to first, and each accepted one goes to the altstack. c_0 ends on top, and samples beyond the 512th stay below c_511. Fewer than 512 accepted samples empty the altstack, and the script fails.
- s1. r = (c_i + V_i) mod q is the centred s1_i + 6144, and r(12288 − r) = 6144² − s1_i² joins the norm sum. One comparison checks the sum against 1024·6144² − β².

## Falcon checks

`falcon_ref.py` is a pure-Python Falcon-512: NTRUSolve key generation, the ffLDL tree and ffSampling. No Falcon library or KAT file was on this machine, so the test vectors come from it with a fixed seed (`build/falcon_vectors.json`). Their norms are about 28M, as expected for Falcon's σ. Each variant below is checked the same way:

- Three signatures pass. The norm sum left by the script equals the Python model's exactly. The bound is exact too: with β² set to a signature's own norm it passes, and with one less it fails.
- Rejected: s2 with one coefficient + 1, another message, one flipped nonce bit, s2 two bytes short, another message's signature, and a signature made with the other variant's HashToPoint.
- With the stream cut to 544 samples (8 blocks, or 34 SHA-256 calls), a nonce that needs more fails (the altstack runs empty) and one that does not passes. SHAKE256: 512th accepted sample at 545 fails, at 543 passes. SHA-256: at 557 fails, at 539 passes.

HashToPoint follows the Falcon specification: SHAKE256(nonce ‖ msg), big-endian 16-bit samples, accepted below 5q. It is not cross-checked against NIST's KAT vectors. FN-DSA (FIPS 206) hashes nonce ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ msg instead; with an empty context that is two more bytes in the same absorbed block, at no extra cost.

## Standard Falcon versus a Bitcoin-specific variant

The variant changes only HashToPoint. Its stream is 39 BIP 340 tagged hashes, SHA256(T ‖ T ‖ nonce ‖ msg ‖ i) with T = SHA256("Falcon512/HashToPoint") and a 1-byte counter i, read as 16 big-endian samples each. Accepting below 5q and reducing mod q are unchanged. `OP_SHA256` replaces 9 Keccak-f[1600] permutations in Script.

| | FN-DSA (SHAKE256) | variant (tagged SHA-256) |
|---|---|---|
| hash to point, with sampling | 131.7M | 9.3M (39 calls, 237k each) |
| varops, three signatures | 162,355,299 to 162,361,435 | 43,505,451 to 43,519,257 |
| unroll charge | 29.7M | 6.9M |
| script bytes (inline) | 8,150 (158,270) | 3,071 (53,063) |
| budget, WU | 16,287 | 4,402 |
| 1-input, 1-output transaction, message unbound, WU | 9,667 | 4,588 |
| weight needed, message unbound, WU | 16,287 | 4,588 |
| fewer than 512 accepted samples | 7.8 × 10^-19 | 3.4 × 10^-24 |
| signers | any FN-DSA signer | needs this HashToPoint |

The variant needs 3.6 times less weight. Its budget alone is 3.7 times smaller, but its spend is bound by its own bytes, not its budget. That changes how it is built. Built first with the standard verifier's 2,560-byte H and M constants and 35 calls, it needed 3,944 WU of budget but its transaction weighed 8,144 WU. So it keeps h as 896 bytes of 14-bit fields and builds H and M in the script:

- H is spread from the fields in groups of 16, with four mask-and-shift steps per group.
- E gets 6145 more per slot (s2 + q instead of s2 + 6144). Every slot of M then needs the same residue, so M = m·U, with U = (2^20480 − 1)/(2^40 − 1) from one `DIV`.

This costs 3.6M varops: the product stage is 10.5M instead of 6.85M. It cuts the script from 6,627 to 3,039 bytes (at 35 calls).

39 calls is the first count at which a short stream is less likely than with 9 Keccak blocks. 35 calls (560 samples) would leave 1.2% of nonces short, so the signer would redraw those. It would save 0.95M varops but only 32 WU, because the spend is bound by its bytes: 42.56M varops and 3,039 script bytes, measured.

The trade-off is compatibility. The keys, the signing algorithm and the norm check are FN-DSA's, but a signature is only valid under the HashToPoint it was made with. Stock FN-DSA libraries and hardware signers cannot produce variant signatures without a change to their hashing. Security should be unaffected: HashToPoint needs to behave like a random oracle, and a domain-separated SHA-256 in counter mode is a standard way to build one. That argument is not a proof, and FIPS 206 does not cover the variant.

## Spends bound to the transaction (`spend.py`, written to `build/spend.json`)

The verifiers above check a signature over a 32-byte message from the witness, so they authorize nothing. With `bound=True`, the script rebuilds the message instead. It is `OP_TX`'s SHA256 over version, locktime, all inputs and outputs, the input index, the annex and the tapleaf hash, with the selector of `shrincs-gsr`'s stage 5. That makes the witness [nonce s2]. A spend whose budget falls short carries an extra witness item below the signature. That item adds only weight, sits outside the signed message, and is dropped at the end.

Each spend is a one-input, one-output transaction of a P2TR output with the single 0xC2 leaf. `build/txeval` (from `shrincs-gsr`, built by `tools/build_txeval.sh`) checks it with Core's `VerifyScript` under the BIP 440 transaction budget and standard flags. Each passes. The same witness in a transaction paying 1 sat less fails, and so does a corrupted s2.

| | FN-DSA (SHAKE256) | variant (tagged SHA-256) |
|---|---|---|
| transaction, WU | 16,289 | 4,566 |
| of which padding, WU | 6,642 | 0 |
| bound by | budget | size |
| varops (budget) | 162,383,758 (162,390,000) | 43,527,995 (45,160,000) |
| script bytes | 8,162 | 3,082 |
| signature bytes (nonce + s2) | 1,064 | 1,064 |

Next to the transaction weights of `shrincs-gsr` (its README, bound by `OP_TX` the same way) and a Schnorr key-path spend:

| one-input, one-output spend | transaction, WU | against Schnorr |
|---|---:|---:|
| Schnorr key path (not post-quantum) | 444 | 1.0× |
| SHRINCS stateful, native opcode | 1,128 | 2.5× |
| SHRINCS stateful, GSR Script | 2,064 | 4.6× |
| Falcon-512, tagged SHA-256 variant, GSR Script | 4,566 | 10.3× |
| SHRINCS stateless, native opcode | 6,245 | 14.1× |
| SHRINCS stateless, GSR Script | 7,409 | 16.7× |
| Falcon-512 (FN-DSA), GSR Script | 16,289 | 36.7× |

## SHAKE256 and Falcon-512 estimate (`estimate.py`, written to `build/estimate.json`)

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
| Kronecker, measured (`falcon.py`) | 30.6M | 162.4M | 16,287 |

The Kronecker figure prices the per-coefficient work as 3 × 512 norm-sized steps, and the NTT figure keeps every value reduced. Both are rough, within perhaps ±30%. They match the earlier `shrincs-gsr/gsr/estimates.py` figure (186M) because the Kronecker route is the same.

The measurement came in 10% under the estimate. The SHAKE256 part (absorbing, 9 permutations with squeezes, sampling) is 131.7M against 136M. The arithmetic is 30.6M against 45M: the s2 norm terms are computed while E is packed, and the fold is two operations on whole numbers instead of per-coefficient work.

## Verdict

A Falcon-512 verifier is a realistic demo: a bound one-input, one-output spend is measured at 16,289 WU, far below the 400k WU standard limit. SHAKE256 is 81% of it: 9 permutations at 1.36k WU each. Hashing to the point with `OP_SHA256` instead brings it to 4,566 WU, at the cost of compatibility with stock FN-DSA signers.

The open costs are the ones a real build would settle:

- s2 must be supplied uncompressed (1,024 bytes). Parsing Falcon's compressed encoding bit by bit in Script would cost more.
- The 9-block squeeze is fixed, so about 1 in 10^18 signatures (7.8 × 10^-19) would need a fresh nonce.
- A signer that redraws the nonce until 8 blocks suffice (41% of nonces) saves a permutation: 147.7M varops, 14,823 WU, measured. The redraw costs only hashing, because the nonce is drawn before the Gaussian sampling. Signatures from an unmodified signer would then fail 59% of the time.
- Karatsuba on the ring product (three 1280 × 1280-byte `MUL`s) would save roughly 1.3M varops, about 130 WU (estimated, not built).
- A cheaper ρπ would help everything Keccak-based, Ethereum-style proofs included. ρπ is 272k of each 566k round.

## Files

- `keccak.py`: the reference, the Script generator, the checks and the measurement.
- `estimate.py`: the representation units, SHAKE256 and Falcon-512.
- `falcon.py`: the Falcon-512 verifier generator for both HashToPoint variants, a Python model of its arithmetic, the checks and the measurement.
- `falcon_ref.py`: Falcon-512 key generation, signing and verification in pure Python, with both HashToPoint variants, for test vectors.
- `spend.py`: Falcon-512 spends bound to their transaction by `OP_TX`, checked and weighed with `txeval`.
- `tools/txeval.cpp`, `tools/build_txeval.sh`: Core's `VerifyScript` under the BIP 440 transaction budget, from `shrincs-gsr`.
- `gsrasm.py`: the token assembler with macros and the `evalscript` runner. It uses `gsr-stark-verifier/risc0-succinct/tools/gsr.py` for minimal pushes.

```
python3 keccak.py && python3 estimate.py && python3 falcon.py && python3 spend.py
```
