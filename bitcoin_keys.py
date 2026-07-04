"""bitcoin_keys.py

Bitcoin key material from a BIP39 seed:
    seed -> master private key (BIP32) -> WIF -> public key -> P2PKH address.

Contains a self-contained pure-Python secp256k1 implementation so the module
does not depend on third-party EC libraries. Base58 / hash160 helpers come from
``crypto_utils``.

Public API:
    seed_to_master_key(seed: bytes) -> bytes               # 32-byte private key
    private_key_to_wif(priv: bytes, compressed=True, testnet=False) -> str
    wif_to_private_key(wif: str) -> tuple[bytes, bool]
    private_key_to_public_key(priv: bytes, compressed=True) -> bytes
    public_key_to_address(pubkey: bytes, testnet=False) -> str
    private_key_to_address(priv: bytes, compressed=True, testnet=False) -> str
"""

import hashlib
import hmac

from crypto_utils import hash160, b58check_encode, b58check_decode

__all__ = [
    "seed_to_master_key",
    "private_key_to_wif",
    "wif_to_private_key",
    "private_key_to_public_key",
    "public_key_to_address",
    "private_key_to_address",
]

# secp256k1 domain parameters.
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


def _inverse_mod(k: int, p: int) -> int:
    """Modular inverse via Python's built-in extended Euclid (pow)."""
    if k == 0:
        raise ZeroDivisionError("division by zero")
    return pow(k % p, -1, p)


def _point_add(a, b):
    """Add two points on secp256k1. ``None`` is the point at infinity."""
    if a is None:
        return b
    if b is None:
        return a
    ax, ay = a
    bx, by = b
    if ax == bx and (ay + by) % _P == 0:
        return None
    if a == b:
        m = (3 * ax * ax) * _inverse_mod(2 * ay, _P)
    else:
        m = (by - ay) * _inverse_mod(bx - ax, _P)
    m %= _P
    rx = (m * m - ax - bx) % _P
    ry = (m * (ax - rx) - ay) % _P
    return (rx, ry)


def _scalar_mult(k: int, point):
    """Multiply ``point`` by scalar ``k`` using double-and-add."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def seed_to_master_key(seed: bytes) -> bytes:
    """Derive the BIP32 master private key (left 32 bytes of HMAC-SHA512)."""
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_priv = i[:32]
    key_int = int.from_bytes(master_priv, "big")
    if key_int == 0 or key_int >= _N:
        raise ValueError("derived an invalid master key; use a different seed")
    return master_priv


def private_key_to_wif(priv: bytes, compressed: bool = True,
                       testnet: bool = False) -> str:
    """Encode a 32-byte private key as Wallet Import Format."""
    if len(priv) != 32:
        raise ValueError("private key must be 32 bytes")
    version = b"\xef" if testnet else b"\x80"
    payload = version + priv
    if compressed:
        payload += b"\x01"
    return b58check_encode(payload)


def wif_to_private_key(wif: str) -> tuple:
    """Decode a WIF string, returning (private_key_bytes, compressed_flag)."""
    payload = b58check_decode(wif)
    payload = payload[1:]  # drop version byte
    if len(payload) == 33 and payload[-1] == 0x01:
        return payload[:32], True
    if len(payload) == 32:
        return payload, False
    raise ValueError("malformed WIF payload")


def private_key_to_public_key(priv: bytes, compressed: bool = True) -> bytes:
    """Compute the secp256k1 public key for a 32-byte private key."""
    if len(priv) != 32:
        raise ValueError("private key must be 32 bytes")
    k = int.from_bytes(priv, "big")
    if k == 0 or k >= _N:
        raise ValueError("private key out of range")
    x, y = _scalar_mult(k, _G)
    if compressed:
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def public_key_to_address(pubkey: bytes, testnet: bool = False) -> str:
    """Build a P2PKH (legacy) Base58Check address from a public key."""
    version = b"\x6f" if testnet else b"\x00"
    return b58check_encode(version + hash160(pubkey))


def private_key_to_address(priv: bytes, compressed: bool = True,
                           testnet: bool = False) -> str:
    """Convenience: private key straight through to a P2PKH address."""
    pubkey = private_key_to_public_key(priv, compressed=compressed)
    return public_key_to_address(pubkey, testnet=testnet)


if __name__ == "__main__":
    # Known vector: private key = 0x01 -> uncompressed/compressed pubkey & address.
    priv = (1).to_bytes(32, "big")
    pub_unc = private_key_to_public_key(priv, compressed=False)
    assert pub_unc.hex() == (
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    ), pub_unc.hex()
    pub_c = private_key_to_public_key(priv, compressed=True)
    assert pub_c.hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    # Compressed address for privkey=1 is a well-known value.
    assert private_key_to_address(priv, compressed=True) == (
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    )
    # WIF round-trip.
    wif = private_key_to_wif(priv, compressed=True)
    back, comp = wif_to_private_key(wif)
    assert back == priv and comp is True
    print("bitcoin_keys self-check passed")
