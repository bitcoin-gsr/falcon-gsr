#!/usr/bin/env python3
"""Checks falcon_ref.py and the Script verifier against the Falcon round-3 known-answer tests.

The vectors are KAT/falcon512-KAT.rsp of falcon-round3.zip from https://falcon-sign.info (100 vectors,
messages of 33 to 3,300 bytes). The file's SHA-256 is checked before use.

Each vector is decoded as the round-3 crypto_sign_open does it: pk = 0x09 || 512 x 14-bit h, and
sm = sig_len (2 bytes) || nonce (40) || msg || 0x29 || compressed s2. Then:

1. HashToPoint is compared with the specification's sampler, and falcon_ref.verify must accept the vector and
   reject it with one message bit flipped or s2_0 + 1.
2. The Script verifier (SHAKE256) runs with the message as a witness item. No KAT message is 32 bytes, so
   only the absorb stage is replaced by one for the vector's message length. The other stages are
   falcon.stages() unchanged. It must accept the vector and reject both changes.

    python3 kat.py [path]   # default build/falcon512-KAT.rsp; writes build/kat.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import falcon
import falcon_ref as ref
from falcon import double_lanes
from gsrasm import Program, evalscript, hx

HERE = Path(__file__).resolve().parent
KAT_SHA256 = "dd75c946fdedef4ec46a2bee7e10c65c9126f1a839b9ced6921fd45f7354b5cd"
N, Q = ref.N, ref.Q


def parse(text: str) -> list[dict]:
    vectors = []
    for line in text.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            if key == "count":
                vectors.append({})
            vectors[-1][key] = value
    return vectors


def modq_decode(buf: bytes) -> list[int]:
    """512 big-endian 14-bit values below q (896 bytes, no spare bits)."""
    assert len(buf) == 14 * N // 8
    acc = int.from_bytes(buf, "big")
    h = [(acc >> 14 * (N - 1 - i)) & 0x3FFF for i in range(N)]
    assert max(h) < Q
    return h


def comp_decode(buf: bytes) -> list[int]:
    """Falcon's compressed s2: sign bit, 7 low bits, the high bits in unary. "-0", values above 2047 and
    trailing nonzero bits or bytes are rejected."""
    bits = "".join(f"{b:08b}" for b in buf)
    pos, s2 = 0, []
    for _ in range(N):
        negative, m = bits[pos] == "1", int(bits[pos + 1:pos + 8], 2)
        pos += 8
        while bits[pos] == "0":
            m += 128
            pos += 1
            assert m <= 2047
        pos += 1
        assert not (negative and m == 0)
        s2.append(-m if negative else m)
    assert len(bits) - pos < 8 and "1" not in bits[pos:]
    return s2


def decode(v: dict) -> tuple[list[int], bytes, bytes, list[int]]:
    """[h, nonce, msg, s2] of a vector."""
    pk, sm = bytes.fromhex(v["pk"]), bytes.fromhex(v["sm"])
    assert pk[0] == 0x09 and len(pk) == 897
    sig_len = int.from_bytes(sm[:2], "big")
    msg_len = len(sm) - 42 - sig_len
    nonce, msg, esig = sm[2:42], sm[42:42 + msg_len], sm[42 + msg_len:]
    assert msg == bytes.fromhex(v["msg"]) and esig[0] == 0x29
    return modq_decode(pk[1:]), nonce, msg, comp_decode(esig[1:])


def hash_to_point_spec(nonce: bytes, msg: bytes) -> list[int]:
    """The specification's HashToPoint, read 2 bytes at a time from SHAKE256(nonce || msg)."""
    stream = hashlib.shake_256(nonce + msg).digest(136 * 64)
    c, i = [], 0
    while len(c) < N:
        t = int.from_bytes(stream[2 * i:2 * i + 2], "big")
        i += 1
        if t < 5 * Q:
            c.append(t % Q)
    return c


def absorb(msg_len: int) -> str:
    """[msg nonce W' V] -> [W' V R0 .. R4]: nonce || msg absorbed into SHAKE256, block by block, which
    leaves the state before the first squeeze, as falcon.stages' one-block absorb does for 32 bytes."""
    blocks = (40 + msg_len) // 136 + 1
    pad_len = 136 * blocks - 40 - msg_len
    pad = b"\x9f" if pad_len == 1 else b"\x1f" + bytes(pad_len - 2) + b"\x80"
    lanes = [5, 5, 5, 2]
    parts = [f"3 ROLL 3 ROLL SIZE 40 NUMEQUALVERIFY SWAP SIZE {msg_len} NUMEQUALVERIFY CAT {hx(pad)} CAT "
             "0 0 0 0 0"]
    for b in range(blocks):
        # [S R0 .. R4]: each row comes up in turn, takes its lanes of block b from S and goes to the top
        for y in range(5):
            parts.append("4 ROLL")
            if y < 4:
                parts.append(f"5 PICK {136 * b + 40 * y} {8 * lanes[y]} SUBSTR {double_lanes(lanes[y])} XOR")
        if b < blocks - 1:
            parts.append("@PERM")
    parts.append("5 ROLL DROP")
    return " ".join(parts)


def program(h: list[int], msg_len: int) -> Program:
    p = falcon.sha3_macros()
    p.macro("GROUP_S2", falcon.group_s2())
    p.macro("SUB_S2", falcon.sub_s2())
    p.macro("GROUP_S1", falcon.group_s1())
    p.macro("SUB_S1", falcon.sub_s1())
    st = [(name, absorb(msg_len) if name == "absorb" else text) for name, text in falcon.stages(h)]
    assert [name for name, _ in st] == ["s2", "product", "absorb", "keccak", "sample", "s1"]
    p.set_main(" ".join(text for _, text in st))
    return p


def check(v: dict) -> dict:
    h, nonce, msg, s2 = decode(v)
    c, samples = ref.hash_to_point(nonce, msg)
    bad_msg = bytes([msg[0] ^ 1]) + msg[1:]
    bad_s2 = [s2[0] + 1] + s2[1:]
    script = program(h, len(msg)).assemble()
    good = evalscript(script, falcon.witness(nonce, msg, s2))
    return {
        "count": int(v["count"]),
        "msg_len": len(msg),
        "samples": samples,
        "hash_to_point": c == hash_to_point_spec(nonce, msg),
        "ref": ref.verify(h, msg, nonce, s2)
               and not ref.verify(h, bad_msg, nonce, s2) and not ref.verify(h, msg, nonce, bad_s2),
        "script": good["success"]
                  and not evalscript(script, falcon.witness(nonce, bad_msg, s2))["success"]
                  and not evalscript(script, falcon.witness(nonce, msg, bad_s2))["success"],
        "varops": good["varops"],
    }


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "build" / "falcon512-KAT.rsp"
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == KAT_SHA256, f"{path} is not the round-3 falcon512-KAT.rsp"
    rows = [check(v) for v in parse(data.decode())]
    res = {
        "vectors": len(rows),
        "hash_to_point": sum(r["hash_to_point"] for r in rows),
        "ref": sum(r["ref"] for r in rows),
        "script": sum(r["script"] for r in rows),
        "max_samples": max(r["samples"] for r in rows),
        "varops": [min(r["varops"] for r in rows), max(r["varops"] for r in rows)],
        "failed": [r["count"] for r in rows if not (r["hash_to_point"] and r["ref"] and r["script"])],
    }
    (HERE / "build").mkdir(exist_ok=True)
    (HERE / "build" / "kat.json").write_text(json.dumps(res | {"rows": rows}, indent=2) + "\n")
    print(json.dumps(res, indent=2))
    assert not res["failed"] and res["max_samples"] <= 68 * falcon.BLOCKS


if __name__ == "__main__":
    main()
