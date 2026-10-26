#!/usr/bin/env python3
"""Falcon-512 spends bound to their transaction, checked and weighed with Core's VerifyScript.

Each variant's verifier runs with `bound=True`: the signed message is OP_TX's SHA256 of the spending
transaction (falcon.OPTX_SELECTOR, as in shrincs-gsr's stage 5), not a witness item. A one-input,
one-output spend of a P2TR output with that single 0xC2 leaf goes through `build/txeval`
(tools/build_txeval.sh), which runs VerifyScript under the BIP 440 transaction budget. A spend whose
varops exceed its budget carries a padding item below the signature, grown until it is funded; the item is
outside the OP_TX message, so the signature stays valid.

Checks per variant: the spend passes; the same witness in a transaction paying 1 sat less fails; a
corrupted s2 fails.

    python3 spend.py        # writes build/spend.json
"""
from __future__ import annotations

import hashlib
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

import falcon
import falcon_ref as ref
from gsrasm import GSR_ROOT

sys.path.insert(0, str(GSR_ROOT / "bitcoin" / "test" / "functional"))
from test_framework.messages import (  # noqa: E402
    COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_string, ser_uint256,
)
from test_framework.script import CScript, LEAF_VERSION_0XC2, taproot_construct  # noqa: E402

HERE = Path(__file__).resolve().parent
TXEVAL = HERE / "build" / "txeval"
# BIP 341's provably unspendable internal key, as in shrincs-gsr
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
FUNDING = COutPoint(int.from_bytes(hashlib.sha256(b"gsr-pq funding").digest(), "little"), 0)
AMOUNT, FEE = 100_000, 5_000


def txeval(tx: CTransaction, spent: list[CTxOut], budget_override: int | None = None) -> dict:
    if not TXEVAL.exists():
        subprocess.run([str(HERE / "tools" / "build_txeval.sh")], check=True, capture_output=True)
    request = {"tx": tx.serialize_with_witness().hex(),
               "spent": [{"amount": o.nValue, "script_pubkey": bytes(o.scriptPubKey).hex()} for o in spent]}
    if budget_override is not None:
        request["budget_override"] = budget_override
    out = subprocess.run([str(TXEVAL)], input=json.dumps(request), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def spend(tap, stack: list[bytes], amount_out: int = AMOUNT - FEE) -> tuple[CTransaction, list[CTxOut]]:
    """A one-input, one-output spend of the single leaf, paying back to the same output script."""
    leaf = tap.leaves["falcon"]
    tx = CTransaction()
    tx.version = 2
    tx.vin = [CTxIn(FUNDING, b"", 0xFFFFFFFD)]
    tx.vout = [CTxOut(amount_out, tap.scriptPubKey)]
    tx.wit.vtxinwit = [CTxInWitness()]
    control = bytes([leaf.version | tap.negflag]) + tap.internal_pubkey + leaf.merklebranch
    tx.wit.vtxinwit[0].scriptWitness.stack = [*stack, bytes(leaf.script), control]
    return tx, [CTxOut(AMOUNT, tap.scriptPubKey)]


def optx_message(tx: CTransaction, spent: list[CTxOut], leaf_hash: bytes) -> bytes:
    """SHA256 of what OPTX_SELECTOR collates for input 0 without an annex, as op_tx.cpp serializes it."""
    out = struct.pack("<III", tx.version, tx.nLockTime, len(tx.vin))
    for txin, prev in zip(tx.vin, spent):
        out += ser_uint256(txin.prevout.hash) + struct.pack("<IQ", txin.prevout.n, prev.nValue)
        out += ser_string(prev.scriptPubKey) + struct.pack("<I", txin.nSequence)
    out += struct.pack("<I", len(tx.vout))
    for o in tx.vout:
        out += struct.pack("<Q", o.nValue) + ser_string(o.scriptPubKey)
    out += struct.pack("<I", 0) + ser_string(b"") + leaf_hash
    return hashlib.sha256(out).digest()


def measure(sk: dict, rng: random.Random, htp: str) -> dict:
    padded = htp == falcon.SHAKE   # the SHAKE256 verifier is bound by its budget, the SHA-256 one by its size
    script = falcon.program(sk["h"], htp=htp, bound=True, padded=padded).assemble()
    tap = taproot_construct(NUMS, [("falcon", CScript(script), LEAF_VERSION_0XC2)])
    tx, spent = spend(tap, [])
    msg = optx_message(tx, spent, tap.leaves["falcon"].leaf_hash)
    sig = ref.sign(sk, msg, rng, ref.hash_to_point if htp == falcon.SHAKE else ref.hash_to_point_sha256)
    items = falcon.witness(sig["nonce"], msg, sig["s2"])[1:]          # [nonce s2]: no message item
    pad = b""

    def stack(nonce_s2: list[bytes] = items) -> list[bytes]:
        return ([pad] if padded else []) + nonce_s2

    tx, spent = spend(tap, stack())
    r = txeval(tx, spent)
    unpadded_weight = r["weight"]
    if not r["inputs"][0]["success"]:
        assert padded and r["inputs"][0]["error"] == "Varops budget exceeded", r["inputs"][0]["error"]
        used = txeval(tx, spent, budget_override=10 ** 12)["inputs"][0]
        assert used["success"], used["error"]
        # start below the need (a padding item over 252 bytes has a 3-byte length) and grow one byte at a time
        pad = bytes(max(0, -(-(used["varops"] - r["budget"]) // 10_000) - 4))
        while not r["inputs"][0]["success"]:
            pad += b"\0"
            tx, spent = spend(tap, stack())
            r = txeval(tx, spent)
    inp = r["inputs"][0]
    assert inp["success"], inp["error"]

    # the same witness in another transaction, and a corrupted s2, must fail
    other, other_spent = spend(tap, stack(), amount_out=AMOUNT - FEE - 1)
    moved = txeval(other, other_spent)["inputs"][0]
    assert not moved["success"]
    bad_s2 = bytearray(items[1])
    bad_s2[200] ^= 1
    corrupted = txeval(*spend(tap, stack([items[0], bytes(bad_s2)])))["inputs"][0]
    assert not corrupted["success"]
    print(f"{htp}: spend passes; other transaction rejected ({moved['error']}); "
          f"corrupted s2 rejected ({corrupted['error']})")

    witness = tx.wit.vtxinwit[0].scriptWitness.stack
    return {
        "tx_weight": r["weight"],
        "varops": inp["varops"],
        "budget": r["budget"],
        "padding_weight": r["weight"] - unpadded_weight,
        "unpadded_tx_weight": unpadded_weight,
        "script_bytes": len(script),
        "signature_bytes": len(items[0]) + len(items[1]),
        "control_block_bytes": len(witness[-1]),
        "witness_items": len(witness),
        "binds": "budget" if r["weight"] > unpadded_weight else "size",
        "checks": {"valid": True, "other_transaction_error": moved["error"],
                   "corrupted_s2_error": corrupted["error"]},
        "tx_hex": tx.serialize_with_witness().hex(),
    }


def main() -> None:
    rng = random.Random(512)
    sk = ref.keygen(rng)
    res = {htp: measure(sk, rng, htp) for htp in (falcon.SHAKE, falcon.SHA)}
    (HERE / "build").mkdir(exist_ok=True)
    (HERE / "build" / "spend.json").write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps({k: {x: y for x, y in v.items() if x != "tx_hex"} for k, v in res.items()}, indent=2))


if __name__ == "__main__":
    main()
