"""
Finite Field Arithmetic and Cryptographic Primitives over Prime Fields.

Implements:
- Prime field arithmetic over F_p (p = 2^127 - 1)
- Modular inverse via Extended Euclidean Algorithm
- Generator and commitment group for verifiable secret sharing
- Deterministic response-to-coordinate mapping
- Hash expansion and key derivation utilities
"""

import hashlib
import hmac
import secrets
from typing import List, Tuple, Sequence

# Primary secret field modulus: Mersenne prime p = 2^127 - 1
PRIME_P: int = (1 << 127) - 1

# Commitment group modulus and generator of order p
# P = 2 * 57 * p + 1 is prime; g has exact order p in Z_P*
COMMITMENT_PRIME_P: int = 19396094914493492417412352623610788052879
COMMITMENT_GENERATOR_G: int = 20769187434139310514121985316880384


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    Computes gcd(a, b) and Bezout coefficients (x, y) such that:
    a * x + b * y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a: int, p: int = PRIME_P) -> int:
    """
    Calculate modular multiplicative inverse of a modulo p:
    a * a^(-1) = 1 (mod p)
    Raises ZeroDivisionError if a is not invertible mod p.
    """
    a = a % p
    if a == 0:
        raise ZeroDivisionError("Modular inverse does not exist for 0 mod p")
    gcd, x, _ = extended_gcd(a, p)
    if gcd != 1:
        raise ValueError(f"Value {a} and modulus {p} are not coprime (gcd = {gcd})")
    return (x % p + p) % p


def field_add(a: int, b: int, p: int = PRIME_P) -> int:
    """Addition in F_p: (a + b) mod p."""
    return (a + b) % p


def field_sub(a: int, b: int, p: int = PRIME_P) -> int:
    """Subtraction in F_p: (a - b) mod p."""
    return (a - b + p) % p


def field_mul(a: int, b: int, p: int = PRIME_P) -> int:
    """Multiplication in F_p: (a * b) mod p."""
    return (a * b) % p


def field_pow(base: int, exp: int, p: int = PRIME_P) -> int:
    """Modular exponentiation in F_p: base^exp mod p."""
    return pow(base, exp, p)


def commitment_pow(base: int, exp: int) -> int:
    """Modular exponentiation in the public commitment group Z_P*."""
    return pow(base, exp % PRIME_P, COMMITMENT_PRIME_P)


def random_field_element(p: int = PRIME_P) -> int:
    """Uniformly sample a random non-zero element in F_p*."""
    while True:
        val = secrets.randbelow(p)
        if val != 0:
            return val


def random_secret(p: int = PRIME_P) -> int:
    """Sample a random master authentication secret S in F_p*."""
    while True:
        s = secrets.randbelow(p)
        if s != 0:
            return s


def hash_secret(secret: int) -> bytes:
    """
    Compute H(S) = SHA-256(S serialized to 16 bytes big-endian).
    Since p = 2^127 - 1 < 2^128, 16 bytes cleanly encapsulates S.
    """
    s_bytes = secret.to_bytes(16, byteorder="big", signed=False)
    return hashlib.sha256(s_bytes).digest()


def hash_to_field(response_bytes: bytes, index: int = 0, p: int = PRIME_P) -> int:
    """
    Map a 320-bit (40 bytes) PUF response deterministically to a non-zero element in F_p*.
    Uses SHA-256 with index salt: (digest + index) % (p - 1) + 1.
    Guarantees result in [1, p-1].
    """
    h = hashlib.sha256(response_bytes + index.to_bytes(4, byteorder="big")).digest()
    raw_int = int.from_bytes(h, byteorder="big")
    val = (raw_int % (p - 1)) + 1
    return val


def map_responses_to_x_coords(responses: Sequence[bytes], p: int = PRIME_P) -> List[int]:
    """
    Map a list of k PUF responses to k distinct, non-zero coordinates in F_p*.
    Guarantees uniqueness among all coordinates.
    """
    x_coords: List[int] = []
    seen = set()
    for j, resp in enumerate(responses):
        offset = 0
        while True:
            coord = hash_to_field(resp, index=offset, p=p)
            if coord not in seen and coord != 0:
                seen.add(coord)
                x_coords.append(coord)
                break
            offset += 1
    return x_coords


def pad_hash(h_bytes: bytes, target_length: int) -> bytes:
    """
    PAD(H(S)): Expands 32-byte H(S) to target_length bytes for XOR masking of J.
    Uses repeated SHA-256 counter expansion:
    SHA-256(H(S) || 0) || SHA-256(H(S) || 1) ... truncated to target_length.
    """
    output = bytearray()
    counter = 0
    while len(output) < target_length:
        ctr_bytes = counter.to_bytes(4, byteorder="big")
        block = hashlib.sha256(h_bytes + ctr_bytes).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:target_length])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Bitwise XOR between two byte sequences of equal length."""
    if len(a) != len(b):
        raise ValueError(f"xor_bytes length mismatch: len(a)={len(a)}, len(b)={len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def hkdf_derive_session_key(n_b: bytes, n_c: bytes, h_s: bytes, key_len: int = 32) -> bytes:
    """
    Derives mutual session key Sk from nonces NB, NC, and secret hash H(S)
    using HKDF-SHA256 (RFC 5869).
    """
    ikm = n_b + n_c + h_s
    salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    info = b"UAV-MutualAuth-SessionKey-v2"
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm[:key_len]
