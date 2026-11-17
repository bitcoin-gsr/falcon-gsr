"""A token assembler for Tapleaf 0xC2 Script with OP_MACRO / OP_CALLMACRO, and an evalscript runner.

Tokens are whitespace-separated; `#` starts a comment:

    DUP 16 LEFT     opcodes and decimal numbers (minimal pushes)
    x0011ff         a data push of these bytes
    @NAME           a reference to the macro NAME

Pushes are minimal (Tapleaf 0xC2 rules). BITCOIN_GSR is a checkout of jmoik/bitcoin `gsr` and
BITCOIN_GSR_BUILD its CMake build directory (default: BITCOIN_GSR/build).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

BITCOIN_GSR = Path(os.environ.get("BITCOIN_GSR", Path(__file__).resolve().parents[1] / "bitcoin"))
BITCOIN_GSR_BUILD = Path(os.environ.get("BITCOIN_GSR_BUILD", BITCOIN_GSR / "build"))
BITCOIN_UTIL = BITCOIN_GSR_BUILD / "bin" / "bitcoin-util"

OPS = {
    "IF": 0x63, "NOTIF": 0x64, "ELSE": 0x67, "ENDIF": 0x68, "VERIFY": 0x69,
    "TOALTSTACK": 0x6B, "FROMALTSTACK": 0x6C, "2DROP": 0x6D, "2DUP": 0x6E, "DROP": 0x75, "DUP": 0x76,
    "NIP": 0x77, "OVER": 0x78, "PICK": 0x79, "ROLL": 0x7A, "ROT": 0x7B, "SWAP": 0x7C, "TUCK": 0x7D,
    "CAT": 0x7E, "SUBSTR": 0x7F, "LEFT": 0x80, "RIGHT": 0x81, "SIZE": 0x82, "INVERT": 0x83, "AND": 0x84,
    "OR": 0x85, "XOR": 0x86, "EQUAL": 0x87, "EQUALVERIFY": 0x88, "2MUL": 0x8D, "ADD": 0x93, "SUB": 0x94,
    "MUL": 0x95, "DIV": 0x96, "MOD": 0x97, "LSHIFT": 0x98, "RSHIFT": 0x99, "NUMEQUALVERIFY": 0x9D,
    "LESSTHAN": 0x9F, "SHA256": 0xA8, "TX": 0xBF, "BYTEREV": 0xCF,
}
OP_MACRO, OP_CALLMACRO = 0xD0, 0xD1


def compact(n: int) -> bytes:
    """CompactSize, up to 0xFFFF."""
    return bytes([n]) if n < 253 else b"\xfd" + n.to_bytes(2, "little")


class Script:
    def __init__(self) -> None:
        self.code = bytearray()

    def data(self, value: bytes) -> None:
        """Minimal push: empty and 1..16 use their opcodes. 0x81 has no legal push in 0xC2 (MINIMALDATA demands
        OP_1NEGATE, an OP_SUCCESS there), so it is built as 0x80 + 1."""
        n = len(value)
        if n == 0 or (n == 1 and 1 <= value[0] <= 16):
            self.int(value[0] if n else 0)
        elif value == b"\x81":
            self.code += bytes([0x01, 0x80, 0x51, OPS["ADD"]])
        else:
            if n <= 75:
                self.code.append(n)
            elif n <= 0xFF:
                self.code += bytes([0x4C, n])
            elif n <= 0xFFFF:
                self.code += bytes([0x4D]) + n.to_bytes(2, "little")
            else:
                self.code += bytes([0x4E]) + n.to_bytes(4, "little")
            self.code += value

    def int(self, n: int) -> None:
        if n <= 16:
            self.code.append(0x50 + n if n else 0x00)
        else:
            self.data(n.to_bytes((n.bit_length() + 7) // 8, "little"))

    def macro(self, body: bytes) -> None:
        self.code += bytes([OP_MACRO]) + compact(len(body)) + body

    def callmacro(self, index: int) -> None:
        self.code += bytes([OP_CALLMACRO]) + compact(index)


def tokens(text: str) -> list[str]:
    return re.sub(r"#[^\n]*", " ", text).split()


def hx(data: bytes) -> str:
    return "x" + data.hex()


def le(value: int) -> str:
    return "x" + value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little").hex()


class Program:
    """Macros in declaration order (a body references only earlier ones) and a main script."""

    def __init__(self) -> None:
        self.macros: dict[str, list[str]] = {}
        self.main: list[str] = []

    def macro(self, name: str, text: str) -> None:
        self.macros[name] = tokens(text)

    def set_main(self, text: str) -> None:
        self.main = tokens(text)

    def _emit(self, toks: list[str], s: Script, index: dict[str, int] | None) -> None:
        for t in toks:
            if t.startswith("@"):
                if index is None:
                    self._emit(self.macros[t[1:]], s, None)
                else:
                    s.callmacro(index[t[1:]])
            elif t.startswith("x"):
                s.data(bytes.fromhex(t[1:]))
            elif re.fullmatch(r"\d+", t):
                s.int(int(t))
            else:
                s.code.append(OPS[t])

    def assemble(self, inline: bool = False) -> bytes:
        s = Script()
        if inline:
            self._emit(self.main, s, None)
            return bytes(s.code)
        index = {}
        for name, body in self.macros.items():
            b = Script()
            self._emit(body, b, index)
            s.macro(bytes(b.code))
            index[name] = len(index)
        self._emit(self.main, s, index)
        return bytes(s.code)


def evalscript(script: bytes, stack: list[bytes], budget: int = 10 ** 12) -> dict:
    request = {"protocol": 1, "sigversion": "tapleaf_0xc2", "script": script.hex(),
               "stack": [x.hex() for x in stack], "varops_budget": budget}
    out = subprocess.run([str(BITCOIN_UTIL), "evalscript"], input=json.dumps(request), capture_output=True,
                         text=True, check=True).stdout
    r = json.loads(out)
    r["varops"] = budget - r["varops-budget-remaining"]
    return r


def cost(text: str, stack: list[bytes]) -> int:
    """Varops of a token sequence run inline on `stack` (success or not)."""
    p = Program()
    p.set_main(text)
    return evalscript(p.assemble(inline=True), stack)["varops"]


def required_wu(varops: int) -> int:
    """Smallest weight whose 0xC2 budget (10,000 x WU - 500,000) covers `varops`."""
    return -(-(varops + 500_000) // 10_000)
