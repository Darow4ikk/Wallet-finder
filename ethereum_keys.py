"""ethereum_keys.py

Ethereum address derivation from a private key:
    private key -> secp256k1 public key -> Keccak-256 -> EIP-55 address.

Self-contained: includes its own pure-Python secp256k1 and Keccak-256, so it
depends only on the standard library and works independently of the other
modules.

Public API:
    private_key_to_public_key(priv: bytes) -> bytes        # 64-byte uncompressed
    public_key_to_address(pubkey: bytes) -> str            # 0x + EIP-55 checksum
    private_key_to_address(priv: bytes) -> str
    keccak256(data: bytes) -> bytes
"""

__all__ = [
    "private_key_to_public_key",
    "public_key_to_address",
    "private_key_to_address",
    "keccak256",
]

# secp256k1 domain parameters.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


# --------------------------------------------------------------------------- #
# secp256k1                                                                    #
# --------------------------------------------------------------------------- #
def _point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    ax, ay = a
    bx, by = b
    if ax == bx and (ay + by) % _P == 0:
        return None
    if a == b:
        m = (3 * ax * ax) * pow(2 * ay, -1, _P)
    else:
        m = (by - ay) * pow(bx - ax, -1, _P)
    m %= _P
    rx = (m * m - ax - bx) % _P
    ry = (m * (ax - rx) - ay) % _P
    return (rx, ry)


def _scalar_mult(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


# --------------------------------------------------------------------------- #
# Keccac-256 (pre-NIST padding, as used by Ethereum)                           #
# --------------------------------------------------------------------------- #
_KECCAK_ROUNDS = 24
_ROTC = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
]
_PILN = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
]
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_MASK64 = (1 << 64) - 1


def _rotl64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f(state):
    for rnd in range(_KECCAK_ROUNDS):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10]
             ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(0, 25, 5):
                state[y + x] ^= d[x]
        # Rho and Pi
        t = state[1]
        for i in range(24):
            j = _PILN[i]
            tmp = state[j]
            state[j] = _rotl64(t, _ROTC[i])
            t = tmp
        # Chi
        for y in range(0, 25, 5):
            row = state[y:y + 5]
            for x in range(5):
                state[y + x] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        # Iota
        state[0] ^= _RC[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 (Ethereum) digest of ``data`` as 32 raw bytes."""
    rate = 136  # 1088 bits for 256-bit output
    state = [0] * 25

    msg = bytearray(data)
    msg.append(0x01)  # Keccak padding (not the 0x06 of SHA3)
    while len(msg) % rate != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80

    for offset in range(0, len(msg), rate):
        block = msg[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(state)

    out = b"".join(state[i].to_bytes(8, "little") for i in range(25))
    return out[:32]


# --------------------------------------------------------------------------- #
# Address derivation                                                           #
# --------------------------------------------------------------------------- #
def private_key_to_public_key(priv: bytes) -> bytes:
    """Return the 64-byte uncompressed public key (X||Y, no 0x04 prefix)."""
    if len(priv) != 32:
        raise ValueError("private key must be 32 bytes")
    k = int.from_bytes(priv, "big")
    if k == 0 or k >= _N:
        raise ValueError("private key out of range")
    x, y = _scalar_mult(k, _G)
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _to_checksum_address(addr_hex: str) -> str:
    """Apply the EIP-55 mixed-case checksum to a lowercase hex address."""
    addr = addr_hex.lower()
    digest = keccak256(addr.encode("ascii")).hex()
    out = "0x"
    for i, char in enumerate(addr):
        if char in "0123456789":
            out += char
        else:
            out += char.upper() if int(digest[i], 16) >= 8 else char
    return out


def public_key_to_address(pubkey: bytes) -> str:
    """Derive the EIP-55 checksummed address from a 64-byte public key."""
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        pubkey = pubkey[1:]
    if len(pubkey) != 64:
        raise ValueError("public key must be 64 bytes (uncompressed, no prefix)")
    addr_bytes = keccak256(pubkey)[-20:]
    return _to_checksum_address(addr_bytes.hex())


def private_key_to_address(priv: bytes) -> str:
    """Convenience: private key straight through to a checksummed address."""
    return public_key_to_address(private_key_to_public_key(priv))


if __name__ == "__main__":
    # Keccak-256 of empty input is a well-known constant.
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    # Known test vector: this private key maps to this address.
    priv = bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    )
    addr = private_key_to_address(priv)
    assert addr == "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23", addr
    print("ethereum_keys self-check passed")
    print("address:", addr)
