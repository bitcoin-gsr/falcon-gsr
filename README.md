# falcon-gsr

Falcon-512 signature verification in Bitcoin Script on the GSR branch (Tapleaf 0xC2, BIP 440/441). SHAKE256 is computed with a Keccak-f[1600] permutation written in Script. All numbers are measured on jmoik/bitcoin `gsr` @ ad6c16f.

## Results

Each spend is a one-input, one-output transaction. It spends a P2TR output whose single 0xC2 leaf holds the verifier and the public key. The signature commits to the spending transaction through `OP_TX`, and each spend passes Core's `VerifyScript` under the BIP 440 budget.

| | Falcon-512 (FN-DSA, SHAKE256) | Falcon-512, tagged SHA-256 HashToPoint |
|---|---:|---:|
| transaction | 16,289 WU | 4,566 WU |
| of which padding to fund the varops budget | 6,642 WU | 0 |
| varops | 162.38M | 43.53M |
| script, including the public key | 8,162 WU | 3,082 WU |
| signature (nonce + uncompressed s2) | 1,064 WU | 1,064 WU |

There is no Keccak opcode, so the standard verifier spends 81% of its varops on SHAKE256 (9 Keccak-f permutations). The variant replaces only HashToPoint, with 39 BIP 340 tagged SHA-256 calls. That makes it 3.6× lighter, but stock FN-DSA signers cannot sign for it.

Compared with SHRINCS ([shrincs-gsr](https://github.com/bitcoin-gsr/shrincs-gsr), bound by `OP_TX` the same way) and a Schnorr key-path spend:

| one-input, one-output spend | transaction | vs Schnorr |
|---|---:|---:|
| Schnorr key path (not post-quantum) | 444 WU | 1.0× |
| SHRINCS stateful, native opcode | 1,128 WU | 2.5× |
| SHRINCS stateful, GSR Script | 2,064 WU | 4.6× |
| Falcon-512, tagged SHA-256, GSR Script | 4,566 WU | 10.3× |
| SHRINCS stateless, native opcode | 6,245 WU | 14.1× |
| SHRINCS stateless, GSR Script | 7,409 WU | 16.7× |
| Falcon-512 (FN-DSA), GSR Script | 16,289 WU | 36.7× |

The native rows exclude the opcode's own validation cost.

## How it works

Falcon verification takes the public key h, a signature (nonce, s2) and a message m. It computes c = HashToPoint(nonce ‖ m) and s1 = c − s2·h mod (q, x^512 + 1), and accepts when ‖(s1, s2)‖² ≤ β².

- **Message.** `OP_TX` collates the version, the locktime, all inputs and outputs, the input index, the annex and the tapleaf hash; m is their SHA256. This is the selector of shrincs-gsr's stage 5.
- **s2.** Each coefficient goes into a 5-byte slot of a Kronecker operand E, and its norm term accumulates below the slots.
- **Ring product.** P = E·H is one `MUL` of two 2,560-byte numbers. The negacyclic fold and the mod-q offsets are one `ADD` and one `SUB` on whole numbers.
- **HashToPoint.** Squeezing 9 SHAKE256 blocks gives 612 samples of 16 bits, big-endian. Samples below 5q are accepted onto the altstack. With fewer than 512 accepted, the script fails; that happens with probability 7.8 × 10⁻¹⁹, and the signer then redraws the nonce.
- **s1 and the norm.** r = (c_i + V_i) mod q gives s1_i, and one comparison checks the norm sum.
- **Padding.** A spend that is short of budget carries an extra witness item below the signature. It sits outside the signed message, and the script drops it.

Verification stages for FN-DSA, measured with the message as a witness item. The bound spend measures 162.38M varops.

| stage | varops |
|---|---:|
| s2: norm terms and the operand E | 10.96M |
| ring product | 6.85M |
| SHAKE256: absorbing, 9 permutations and squeezes | 122.94M |
| sampling 612 values | 8.81M |
| s1 and the norm check | 12.80M |
| total, including a 29.7M macro unroll charge | 162.36M |

The SHA-256 variant is limited by its own size, not its budget. So it stores h as 896 bytes of 14-bit fields and builds the 2,560-byte operands in Script. Its product stage costs 10.5M varops instead of 6.85M, and its script is 3 KB instead of 8 KB. Hashing costs 9.3M varops.

### Keccak-f[1600]

The state is five 80-byte rows. Each lane is stored twice (lane ‖ lane) in a 16-byte slot, so rotating a lane by r is one shift of its row: the low 8 bytes of `row >> (128x + 64 − r)`. θ and χ work on whole rows, and the rounds are macros.

| | varops | script | WU needed |
|---|---:|---:|---:|
| with macros | 13,560,872 (2,533,472 unroll charge) | 1,008 WU | 1,407 |
| inline | 11,027,400 | 12,096 WU | 12,096 |

WU needed = ceil((varops + 500,000) / 10,000), or the script's own size if that is larger.

A round costs 566k varops. Measured inline, ρπ is 272k, χ 111k and θ 69k. The two simpler layouts cost more:

- 25 separate 8-byte lanes pay fixed charges per lane. An 8-byte XOR costs 1,622 varops, against 3,350 for all 200 bytes at once.
- A flat 200-byte state makes the per-lane ρπ dearer: 6,068 varops to cut a lane out and 7,008 to rotate it.

The layout follows shrincs-gsr's `keccak.py` (14,425,040 varops). This version saves 6% through its θ and χ stack handling.

## Checks

- **Keccak.** Inside a Python sponge, the Script permutation reproduces hashlib's SHA3-256 and SHAKE256, including a two-block squeeze. One flipped input bit is rejected, and all-zero and all-one states match.
- **Falcon.** `falcon_ref.py` is a pure-Python Falcon-512 (NTRUSolve, ffLDL, ffSampling) that generates the test vectors.
  - Three signatures per variant pass.
  - The script's norm sum equals the model's. The bound is exact: a signature passes at β² equal to its own norm and fails one below.
  - These are rejected: a changed s2 coefficient, a different message, a flipped nonce bit, a short s2, another message's signature, the other variant's signature, and a stream with too few samples.
- **Spends.** Each spend passes `VerifyScript`. The same witness in a transaction paying 1 sat less fails, and so does a corrupted s2.

## Limitations

- s2 is supplied uncompressed (1,024 bytes). Parsing Falcon's compressed encoding in Script would cost more.
- HashToPoint follows the Falcon specification but is not cross-checked against NIST's KAT vectors. FIPS 206 prefixes the message with 0x00 ‖ len(ctx) ‖ ctx. With an empty context, that is two bytes in the same block, at no extra cost.
- `OP_TX` is a draft opcode of the gsr branch.
- Possible savings:
  - A signer that redraws the nonce until 8 SHAKE256 blocks suffice (41% of nonces) saves one permutation, about 1.5k WU.
  - Karatsuba on the ring product would save about 130 WU (estimated).

## Running

This needs [gsr-stark-verifier](https://github.com/jmoik/gsr-stark-verifier) checked out next to this repo, or `GSR_ROOT` pointing to it, with its gsr build: `bitcoin-util`, the static libraries and the functional test framework. Results go to `build/*.json`.

```
python3 keccak.py      # Keccak checks and cost
python3 falcon.py      # verifier tests and stage costs (message as a witness item)
python3 spend.py       # OP_TX-bound spends through VerifyScript
python3 estimate.py    # unit costs, and an NTT-based estimate (about 34k WU) that the Kronecker MUL beats
```

Other files:
- `falcon_ref.py`: the reference Falcon-512.
- `gsrasm.py`: the assembler with macros, and the `evalscript` runner.
- `tools/txeval.cpp`: Core's `VerifyScript` under the BIP 440 budget, from shrincs-gsr.
