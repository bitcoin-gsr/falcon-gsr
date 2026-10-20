#!/usr/bin/env python3
"""Falcon-512 in pure Python: key generation, signing and verification, to make test vectors.

It follows the Falcon specification (round 3; FN-DSA keeps the same core): NTRUGen with NTRUSolve and Babai
reduction, the ffLDL tree, ffSampling with SamplerZ, and HashToPoint over SHAKE256(nonce || message). It is
neither constant time nor secure (Python floats, Python's `random`), and it does not encode keys or signatures.
Its purpose is signatures whose s2 has Falcon's distribution, for the Script verifier in falcon.py.

    python3 falcon_ref.py   # keygen, sign, verify, and a rejected forgery
"""
from __future__ import annotations

import cmath
import hashlib
import math
import random

N = 512
Q = 12289
SIGMA = 165.7366171829776          # signing standard deviation for n = 512
SIGMA_FG = 1.17 * math.sqrt(Q / (2 * N))
BETA2 = 34034726                   # floor(beta^2) for n = 512
NONCE_LEN = 40


# ---- hash to point ----

def hash_to_point(nonce: bytes, msg: bytes, n: int = N) -> tuple[list[int], int]:
    """c = HashToPoint(nonce || msg): big-endian 16-bit samples below 5q, reduced mod q.
    Also returns the number of samples read."""
    out, i, c = b"", 0, []
    while len(c) < n:
        if 2 * i + 2 > len(out):
            out = hashlib.shake_256(nonce + msg).digest(max(2 * len(out), 136 * 9))
        t = (out[2 * i] << 8) | out[2 * i + 1]
        i += 1
        if t < 5 * Q:
            c.append(t % Q)
    return c, i


SHA_TAG = b"Falcon512/HashToPoint"
SHA_CALLS = 39                     # 624 samples: fewer than 512 accepted with probability 3.4e-24


def tagged_hash(tag: bytes, data: bytes) -> bytes:
    """BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    t = hashlib.sha256(tag).digest()
    return hashlib.sha256(t + t + data).digest()


def hash_to_point_sha256(nonce: bytes, msg: bytes, calls: int = SHA_CALLS, n: int = N) -> tuple[list[int] | None, int]:
    """A Bitcoin-specific HashToPoint, not FN-DSA: the stream is the tagged hashes of nonce || msg || i for a
    1-byte counter i = 0 .. calls - 1, read as big-endian 16-bit samples, accepted below 5q and reduced mod q.
    None if fewer than n samples are accepted; the signer then draws another nonce."""
    out = b"".join(tagged_hash(SHA_TAG, nonce + msg + bytes([i])) for i in range(calls))
    c, i = [], 0
    while len(c) < n and 2 * i + 2 <= len(out):
        t = (out[2 * i] << 8) | out[2 * i + 1]
        i += 1
        if t < 5 * Q:
            c.append(t % Q)
    return (c if len(c) == n else None), i


# ---- integer polynomials mod x^n + 1 ----

def mul_z(a: list[int], b: list[int]) -> list[int]:
    """Exact product mod x^n + 1 by Kronecker substitution with signed digits."""
    n = len(a)
    bound = max(1, max(map(abs, a))) * max(1, max(map(abs, b))) * n
    k = bound.bit_length() + 2
    pa = sum(x << (k * i) for i, x in enumerate(a))
    pb = sum(x << (k * i) for i, x in enumerate(b))
    p = pa * pb
    mask, half, full = (1 << k) - 1, 1 << (k - 1), []
    for _ in range(2 * n - 1):
        d = p & mask
        if d >= half:
            d -= 1 << k
        full.append(d)
        p = (p - d) >> k
    full.append(0)
    return [full[i] - full[i + n] for i in range(n)]


def field_norm(f: list[int]) -> list[int]:
    """N(f) = f0^2 - x f1^2 in the ring of half degree, for f = f0(x^2) + x f1(x^2)."""
    f0, f1 = f[0::2], f[1::2]
    a, b = mul_z(f0, f0), mul_z(f1, f1)
    xb = [-b[-1]] + b[:-1]
    return [x - y for x, y in zip(a, xb)]


def galois_conjugate(f: list[int]) -> list[int]:
    return [x if i % 2 == 0 else -x for i, x in enumerate(f)]


def lift(a: list[int]) -> list[int]:
    out = [0] * (2 * len(a))
    out[0::2] = a
    return out


# ---- FFT over C[x]/(x^n + 1) and NTT over Z_q[x]/(x^n + 1), with the same evaluation order ----
# The points of size n are, as exponents of a primitive 1024th root, [w_0, -w_0, w_1, -w_1, ...] where w_k is
# a square root of point k of size n/2; the single point of size 1 is -1. Splitting and merging pair them up.

def _points() -> dict[int, list[int]]:
    pts = {1: [512]}
    n = 2
    while n <= N:
        pts[n] = [e for p in pts[n // 2] for e in (p // 2, p // 2 + 512)]
        n *= 2
    return pts


PTS = _points()
ROOT_C = [cmath.exp(2j * math.pi * e / 1024) for e in range(1024)]
PSI = next(pow(g, (Q - 1) // 1024, Q) for g in range(2, Q) if pow(g, (Q - 1) // 2, Q) != 1)
ROOT_Q = [pow(PSI, e, Q) for e in range(1024)]


def merge_fft(f0: list[complex], f1: list[complex]) -> list[complex]:
    w = [ROOT_C[e] for e in PTS[2 * len(f0)][0::2]]
    out = []
    for a, b, wk in zip(f0, f1, w):
        out += [a + wk * b, a - wk * b]
    return out


def split_fft(f: list[complex]) -> tuple[list[complex], list[complex]]:
    w = [ROOT_C[e] for e in PTS[len(f)][0::2]]
    f0 = [(f[2 * k] + f[2 * k + 1]) / 2 for k in range(len(f) // 2)]
    f1 = [(f[2 * k] - f[2 * k + 1]) / (2 * w[k]) for k in range(len(f) // 2)]
    return f0, f1


def fft(f: list) -> list[complex]:
    if len(f) == 1:
        return [complex(f[0])]
    return merge_fft(fft(f[0::2]), fft(f[1::2]))


def ifft(f: list[complex]) -> list[float]:
    if len(f) == 1:
        return [f[0].real]
    f0, f1 = split_fft(f)
    out = [0.0] * len(f)
    out[0::2], out[1::2] = ifft(f0), ifft(f1)
    return out


def ntt(f: list[int]) -> list[int]:
    if len(f) == 1:
        return [f[0] % Q]
    a, b = ntt(f[0::2]), ntt(f[1::2])
    w = [ROOT_Q[e] for e in PTS[len(f)][0::2]]
    out = []
    for x, y, wk in zip(a, b, w):
        out += [(x + wk * y) % Q, (x - wk * y) % Q]
    return out


def intt(f: list[int]) -> list[int]:
    if len(f) == 1:
        return [f[0] % Q]
    w = [ROOT_Q[e] for e in PTS[len(f)][0::2]]
    inv2 = pow(2, -1, Q)
    f0 = [(f[2 * k] + f[2 * k + 1]) * inv2 % Q for k in range(len(f) // 2)]
    f1 = [(f[2 * k] - f[2 * k + 1]) * inv2 * pow(w[k], -1, Q) % Q for k in range(len(f) // 2)]
    out = [0] * len(f)
    out[0::2], out[1::2] = intt(f0), intt(f1)
    return out


def mul_zq(a: list[int], b: list[int]) -> list[int]:
    return intt([x * y % Q for x, y in zip(ntt(a), ntt(b))])


# ---- key generation ----

def samplerz(mu: float, sigma: float, rng: random.Random) -> int:
    """A discrete Gaussian over the integers, centre mu, by inversion over +-12 sigma."""
    lo = math.floor(mu - 12 * sigma) - 1
    zs = range(lo, math.ceil(mu + 12 * sigma) + 2)
    ws = [math.exp(-(z - mu) ** 2 / (2 * sigma * sigma)) for z in zs]
    u = rng.random() * sum(ws)
    for z, w in zip(zs, ws):
        u -= w
        if u <= 0:
            return z
    return zs[-1]


def xgcd(a: int, b: int) -> tuple[int, int, int]:
    """d, u, v with u a + v b = d = gcd(a, b) >= 0."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        qt, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - qt * x1
        y0, y1 = y1, y0 - qt * y1
    return (a, x0, y0) if a >= 0 else (-a, -x0, -y0)


def bitsize(a: int) -> int:
    return (abs(a).bit_length() + 7) // 8 * 8


def reduce(f: list[int], g: list[int], F: list[int], G: list[int]) -> tuple[list[int], list[int]]:
    """Babai reduction of (F, G) against (f, g), on 53-bit approximations (as in the reference)."""
    size = max(53, *(bitsize(x) for x in f + g))
    fa = fft([x >> (size - 53) for x in f])
    ga = fft([x >> (size - 53) for x in g])
    den = [a * a.conjugate() + b * b.conjugate() for a, b in zip(fa, ga)]
    while True:
        Size = max(53, *(bitsize(x) for x in F + G))
        if Size < size:
            break
        Fa = fft([x >> (Size - 53) for x in F])
        Ga = fft([x >> (Size - 53) for x in G])
        k = [round(x) for x in ifft([(A * a.conjugate() + B * b.conjugate()) / d
                                     for A, B, a, b, d in zip(Fa, Ga, fa, ga, den)])]
        if not any(k):
            break
        fk, gk = mul_z(f, k), mul_z(g, k)
        F = [x - (y << (Size - size)) for x, y in zip(F, fk)]
        G = [x - (y << (Size - size)) for x, y in zip(G, gk)]
    return F, G


def ntru_solve(f: list[int], g: list[int]) -> tuple[list[int], list[int]]:
    """F, G with f G - g F = q (mod x^n + 1)."""
    if len(f) == 1:
        d, u, v = xgcd(f[0], g[0])
        if d != 1:
            raise ValueError("resultants not coprime")
        return [-Q * v], [Q * u]
    Fp, Gp = ntru_solve(field_norm(f), field_norm(g))
    F = mul_z(lift(Fp), galois_conjugate(g))
    G = mul_z(lift(Gp), galois_conjugate(f))
    return reduce(f, g, F, G)


def gs_norm2(f: list[int], g: list[int]) -> float:
    """Squared Gram-Schmidt norm of the NTRU basis: max(||(g, -f)||^2, ||q (f*, g*) / (ff* + gg*)||^2)."""
    fa, ga = fft(f), fft(g)
    first = sum(x * x for x in f + g)
    second = Q * Q / len(f) * sum(1 / (abs(a) ** 2 + abs(b) ** 2) for a, b in zip(fa, ga))
    return max(first, second)


def keygen(rng: random.Random) -> dict:
    while True:
        f = [samplerz(0, SIGMA_FG, rng) for _ in range(N)]
        g = [samplerz(0, SIGMA_FG, rng) for _ in range(N)]
        if gs_norm2(f, g) > 1.17 ** 2 * Q:
            continue
        fn = ntt(f)
        if 0 in fn:
            continue
        try:
            F, G = ntru_solve(f, g)
        except ValueError:
            continue
        fG, gF = mul_z(f, G), mul_z(g, F)
        assert [a - b for a, b in zip(fG, gF)] == [Q] + [0] * (N - 1), "NTRU equation"
        h = intt([b * pow(a, -1, Q) % Q for a, b in zip(fn, ntt(g))])
        return {"f": f, "g": g, "F": F, "G": G, "h": h, "tree": signing_tree(f, g, F, G)}


# ---- signing ----

def ffldl(g00: list[complex], g01: list[complex], g11: list[complex]):
    """ffLDL* tree of the self-adjoint 2x2 matrix [[g00, g01], [g01*, g11]], leaves normalized to sigma'."""
    l10 = [b.conjugate() / a for a, b in zip(g00, g01)]
    d11 = [c - abs(l) ** 2 * a for a, c, l in zip(g00, g11, l10)]
    if len(g00) == 1:
        return l10, SIGMA / math.sqrt(g00[0].real), SIGMA / math.sqrt(d11[0].real)
    d0, d1 = split_fft(g00)
    e0, e1 = split_fft(d11)
    return l10, ffldl(d0, d1, d0), ffldl(e0, e1, e0)


def signing_tree(f, g, F, G):
    fa, ga, Fa, Ga = map(fft, (f, g, F, G))
    g00 = [a * a.conjugate() + b * b.conjugate() for a, b in zip(ga, fa)]
    g01 = [a * c.conjugate() + b * d.conjugate() for a, b, c, d in zip(ga, fa, Ga, Fa)]
    g11 = [c * c.conjugate() + d * d.conjugate() for c, d in zip(Ga, Fa)]
    return ffldl(g00, g01, g11)


def ffsampling(t0: list[complex], t1: list[complex], tree, rng: random.Random):
    """z close to t, Gaussian around it, in FFT form."""
    if len(t0) == 1:
        l10, s0, s1 = tree
        z1 = samplerz(t1[0].real, s1, rng)
        z0 = samplerz((t0[0] + (t1[0] - z1) * l10[0]).real, s0, rng)
        return [complex(z0)], [complex(z1)]
    l10, T0, T1 = tree
    z1 = merge_fft(*ffsampling(*split_fft(t1), T1, rng))
    t0b = [a + (b - c) * l for a, b, c, l in zip(t0, t1, z1, l10)]
    z0 = merge_fft(*ffsampling(*split_fft(t0b), T0, rng))
    return z0, z1


def sign(sk: dict, msg: bytes, rng: random.Random, htp=hash_to_point) -> dict:
    """A signature (nonce, s1, s2) with s1 + s2 h = c mod q and ||(s1, s2)||^2 <= beta^2, for c = htp(nonce, msg)."""
    f, g, F, G = sk["f"], sk["g"], sk["F"], sk["G"]
    fa, Fa = fft(f), fft(F)
    while True:
        nonce = rng.randbytes(NONCE_LEN)
        c, _ = htp(nonce, msg)
        if c is None:
            continue
        ca = fft(c)
        t0 = [-x * y / Q for x, y in zip(ca, Fa)]
        t1 = [x * y / Q for x, y in zip(ca, fa)]
        z0, z1 = (list(map(round, ifft(z))) for z in ffsampling(t0, t1, sk["tree"], rng))
        # s = (c, 0) - z B with B = [[g, -f], [G, -F]], in exact integers
        s1 = [a - b - d for a, b, d in zip(c, mul_z(z0, g), mul_z(z1, G))]
        s2 = [a + b for a, b in zip(mul_z(z0, f), mul_z(z1, F))]
        if sum(x * x for x in s1 + s2) <= BETA2:
            return {"nonce": nonce, "s1": s1, "s2": s2}


# ---- verification ----

def centered(x: int) -> int:
    x %= Q
    return x - Q if x > Q // 2 else x


def verify(h: list[int], msg: bytes, nonce: bytes, s2: list[int], htp=hash_to_point) -> bool:
    c, _ = htp(nonce, msg)
    if c is None:
        return False
    s1 = [centered(a - b) for a, b in zip(c, mul_zq([x % Q for x in s2], h))]
    return sum(x * x for x in s1) + sum(x * x for x in s2) <= BETA2


def main() -> None:
    import time
    rng = random.Random(512)
    t = time.time()
    sk = keygen(rng)
    print(f"keygen {time.time() - t:.1f}s, |F|max {max(map(abs, sk['F']))}")
    for i in range(3):
        msg = bytes([i]) * 32
        sig = sign(sk, msg, rng)
        assert verify(sk["h"], msg, sig["nonce"], sig["s2"])
        assert [centered(x) for x in sig["s1"]] == sig["s1"]
        norm = sum(x * x for x in sig["s1"] + sig["s2"])
        print(f"sig {i}: norm^2 {norm}, max|s2| {max(map(abs, sig['s2']))}, ok")
        bad = list(sig["s2"])
        bad[7] += 1
        assert not verify(sk["h"], msg, sig["nonce"], bad)
        assert not verify(sk["h"], bytes([i + 1]) * 32, sig["nonce"], sig["s2"])
    print("rejects a changed s2 coefficient and a changed message")


if __name__ == "__main__":
    main()
