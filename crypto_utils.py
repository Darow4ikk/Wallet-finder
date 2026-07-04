"""crypto_utils.py

Low-level cryptographic helpers used by the other modules.

Only the standard library ``hashlib`` is imported. RIPEMD-160 is implemented
in pure Python so the module works even on builds of OpenSSL where
``hashlib.new("ripemd160")`` is unavailable. Base58 / Base58Check are also
implemented from scratch.

Public API:
    sha256(data: bytes) -> bytes
    double_sha256(data: bytes) -> bytes
    ripemd160(data: bytes) -> bytes
    hash160(data: bytes) -> bytes
    b58encode(data: bytes) -> str
    b58decode(text: str) -> bytes
    b58check_encode(payload: bytes) -> str
    b58check_decode(text: str) -> bytes
"""

import hashlib

__all__ = [
    "sha256",
    "double_sha256",
    "ripemd160",
    "hash160",
    "b58encode",
    "b58decode",
    "b58check_encode",
    "b58check_decode",
]

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# --------------------------------------------------------------------------- #
# SHA-256 (delegated to hashlib)                                              #
# --------------------------------------------------------------------------- #
def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of ``data`` as 32 raw bytes."""
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    """Return SHA-256(SHA-256(data)) as 32 raw bytes."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


# --------------------------------------------------------------------------- #
# RIPEMD-160 (pure-Python implementation, RFC reference)                       #
# --------------------------------------------------------------------------- #
def _rol(x: int, n: int) -> int:
    """32-bit left rotate."""
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# Message word selection per round (left and right lines).
_RL = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]
_RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]
# Rotate amounts (left and right lines).
_SL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]
_SR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]
# Round constants (left and right lines).
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def _f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160(data: bytes) -> bytes:
    """Return the RIPEMD-160 digest of ``data`` as 20 raw bytes."""
    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )

    msg = bytearray(data)
    orig_len_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += orig_len_bits.to_bytes(8, "little")

    for chunk_start in range(0, len(msg), 64):
        block = msg[chunk_start:chunk_start + 64]
        x = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]

        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4

        for j in range(80):
            rnd = j // 16
            t = (al + _f(j, bl, cl, dl) + x[_RL[j]] + _KL[rnd]) & 0xFFFFFFFF
            t = (_rol(t, _SL[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t

            t = (ar + _f(79 - j, br, cr, dr) + x[_RR[j]] + _KR[rnd]) & 0xFFFFFFFF
            t = (_rol(t, _SR[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t

        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t

    return b"".join(
        h.to_bytes(4, "little") for h in (h0, h1, h2, h3, h4)
    )


def hash160(data: bytes) -> bytes:
    """Return RIPEMD-160(SHA-256(data)) as 20 raw bytes."""
    return ripemd160(sha256(data))


# --------------------------------------------------------------------------- #
# Base58 / Base58Check                                                         #
# --------------------------------------------------------------------------- #
def b58encode(data: bytes) -> str:
    """Encode raw bytes to a Base58 string."""
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out

    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return _B58_ALPHABET[0] * leading_zeros + out


def b58decode(text: str) -> bytes:
    """Decode a Base58 string back to raw bytes."""
    n = 0
    for char in text:
        index = _B58_ALPHABET.find(char)
        if index == -1:
            raise ValueError(f"invalid Base58 character: {char!r}")
        n = n * 58 + index

    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
    leading_zeros = len(text) - len(text.lstrip(_B58_ALPHABET[0]))
    return b"\x00" * leading_zeros + body


def b58check_encode(payload: bytes) -> str:
    """Append a 4-byte double-SHA256 checksum and Base58-encode the result."""
    checksum = double_sha256(payload)[:4]
    return b58encode(payload + checksum)


def b58check_decode(text: str) -> bytes:
    """Decode a Base58Check string, verify the checksum, return the payload."""
    raw = b58decode(text)
    if len(raw) < 4:
        raise ValueError("Base58Check string too short")
    payload, checksum = raw[:-4], raw[-4:]
    if double_sha256(payload)[:4] != checksum:
        raise ValueError("invalid Base58Check checksum")
    return payload


if __name__ == "__main__":
    # Quick self-check against well-known test vectors.
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert b58decode(b58encode(b"\x00\x00hello")) == b"\x00\x00hello"
    assert b58check_decode(b58check_encode(b"\x00payload")) == b"\x00payload"
    print("crypto_utils self-check passed")
