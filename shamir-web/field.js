/**
 * Finite Field Arithmetic and Cryptographic Primitives over Prime Fields.
 * BigInt implementation matching crypto/finite_field.py.
 */

// Primary secret field modulus: Mersenne prime p = 2^127 - 1
export const PRIME_P = (1n << 127n) - 1n;

// Commitment group modulus and generator of order p
// P = 2 * 57 * p + 1 is prime; g has exact order p in Z_P*
export const COMMITMENT_PRIME_P = 19396094914493492417412352623610788052879n;
export const COMMITMENT_GENERATOR_G = 20769187434139310514121985316880384n;

/**
 * Extended Euclidean Algorithm for BigInt.
 * Computes gcd(a, b) and Bezout coefficients (x, y).
 */
export function extendedGcd(a, b) {
    if (a === 0n) {
        return [b, 0n, 1n];
    }
    const [gcd, x1, y1] = extendedGcd(b % a, a);
    const x = y1 - (b / a) * x1;
    const y = x1;
    return [gcd, x, y];
}

/**
 * Modular Multiplicative Inverse of a modulo p: a * a^(-1) = 1 (mod p).
 */
export function modInverse(a, p = PRIME_P) {
    a = ((a % p) + p) % p;
    if (a === 0n) {
        throw new Error("Modular inverse does not exist for 0 mod p");
    }
    const [gcd, x] = extendedGcd(a, p);
    if (gcd !== 1n) {
        throw new Error(`Value ${a} and modulus ${p} are not coprime`);
    }
    return ((x % p) + p) % p;
}

export function fieldAdd(a, b, p = PRIME_P) {
    return ((BigInt(a) + BigInt(b)) % p + p) % p;
}

export function fieldSub(a, b, p = PRIME_P) {
    return ((BigInt(a) - BigInt(b)) % p + p) % p;
}

export function fieldMul(a, b, p = PRIME_P) {
    return ((BigInt(a) * BigInt(b)) % p + p) % p;
}

export function fieldPow(base, exp, p = PRIME_P) {
    base = ((BigInt(base) % p) + p) % p;
    exp = BigInt(exp);
    let res = 1n;
    while (exp > 0n) {
        if (exp & 1n) {
            res = (res * base) % p;
        }
        base = (base * base) % p;
        exp >>= 1n;
    }
    return res;
}

export function commitmentPow(base, exp, pGroup = COMMITMENT_PRIME_P, pSub = PRIME_P) {
    base = ((BigInt(base) % pGroup) + pGroup) % pGroup;
    let exponent = ((BigInt(exp) % pSub) + pSub) % pSub;
    let res = 1n;
    while (exponent > 0n) {
        if (exponent & 1n) {
            res = (res * base) % pGroup;
        }
        base = (base * base) % pGroup;
        exponent >>= 1n;
    }
    return res;
}

/**
 * Generates a uniform random BigInt in [1, p-1].
 */
export function randomFieldElement(p = PRIME_P) {
    const bytes = new Uint8Array(16);
    while (true) {
        if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.getRandomValues) {
            globalThis.crypto.getRandomValues(bytes);
        } else {
            for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
        }
        let val = 0n;
        for (let i = 0; i < 16; i++) {
            val = (val << 8n) | BigInt(bytes[i]);
        }
        val = val % p;
        if (val > 0n) return val;
    }
}

export function randomSecret(p = PRIME_P) {
    return randomFieldElement(p);
}

/**
 * SHA-256 hash helper (sync/async compatible).
 */
export async function sha256Bytes(data) {
    const buffer = data instanceof Uint8Array ? data : new Uint8Array(data);
    const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', buffer);
    return new Uint8Array(hashBuffer);
}

/**
 * Serializes secret S into 16-byte big-endian representation.
 */
export function secretToBytes(secret) {
    let s = BigInt(secret);
    const bytes = new Uint8Array(16);
    for (let i = 15; i >= 0; i--) {
        bytes[i] = Number(s & 0xFFn);
        s >>= 8n;
    }
    return bytes;
}

/**
 * Compute H(S) = SHA-256(secretToBytes(S)).
 */
export async function hashSecret(secret) {
    const sBytes = secretToBytes(secret);
    return await sha256Bytes(sBytes);
}

/**
 * Deterministic mapping of 320-bit response to element in F_p*.
 */
export async function hashToField(responseBytes, index = 0, p = PRIME_P) {
    const idxBytes = new Uint8Array(4);
    idxBytes[0] = (index >> 24) & 0xFF;
    idxBytes[1] = (index >> 16) & 0xFF;
    idxBytes[2] = (index >> 8) & 0xFF;
    idxBytes[3] = index & 0xFF;

    const payload = new Uint8Array(responseBytes.length + 4);
    payload.set(responseBytes);
    payload.set(idxBytes, responseBytes.length);

    const digest = await sha256Bytes(payload);
    let raw = 0n;
    for (let i = 0; i < digest.length; i++) {
        raw = (raw << 8n) | BigInt(digest[i]);
    }
    return (raw % (p - 1n)) + 1n;
}

/**
 * Map k PUF responses to k distinct, non-zero coordinates in F_p*.
 */
export async function mapResponsesToXCoords(responses, p = PRIME_P) {
    const xCoords = [];
    const seen = new Set();
    for (let j = 0; j < responses.length; j++) {
        let offset = 0;
        while (true) {
            const coord = await hashToField(responses[j], offset, p);
            const key = coord.toString();
            if (!seen.has(key) && coord !== 0n) {
                seen.add(key);
                xCoords.push(coord);
                break;
            }
            offset++;
        }
    }
    return xCoords;
}

/**
 * PAD(H(S)): Expands 32-byte H(S) to targetLength bytes via counter expansion.
 */
export async function padHash(hBytes, targetLength) {
    const output = new Uint8Array(targetLength);
    let written = 0;
    let counter = 0;
    while (written < targetLength) {
        const ctrBytes = new Uint8Array(4);
        ctrBytes[0] = (counter >> 24) & 0xFF;
        ctrBytes[1] = (counter >> 16) & 0xFF;
        ctrBytes[2] = (counter >> 8) & 0xFF;
        ctrBytes[3] = counter & 0xFF;

        const input = new Uint8Array(hBytes.length + 4);
        input.set(hBytes);
        input.set(ctrBytes, hBytes.length);

        const block = await sha256Bytes(input);
        const toCopy = Math.min(block.length, targetLength - written);
        output.set(block.subarray(0, toCopy), written);
        written += toCopy;
        counter++;
    }
    return output;
}

export function xorBytes(a, b) {
    if (a.length !== b.length) {
        throw new Error(`xorBytes length mismatch: a=${a.length}, b=${b.length}`);
    }
    const res = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
        res[i] = a[i] ^ b[i];
    }
    return res;
}

/**
 * HMAC-SHA256 computation using Web Crypto API.
 */
export async function hmacSha256(keyBytes, dataBytes) {
    const key = await globalThis.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: { name: "SHA-256" } },
        false,
        ["sign"]
    );
    const signature = await globalThis.crypto.subtle.sign("HMAC", key, dataBytes);
    return new Uint8Array(signature);
}

/**
 * Constant-time equality comparison between two Uint8Arrays.
 */
export function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

/**
 * HKDF-SHA256 session key derivation (RFC 5869).
 */
export async function hkdfDeriveSessionKey(nb, nc, hs, keyLen = 32) {
    const ikm = new Uint8Array(nb.length + nc.length + hs.length);
    ikm.set(nb, 0);
    ikm.set(nc, nb.length);
    ikm.set(hs, nb.length + nc.length);

    const salt = new Uint8Array(32);
    const prk = await hmacSha256(salt, ikm);

    const info = new TextEncoder().encode("UAV-MutualAuth-SessionKey-v2");
    const infoPayload = new Uint8Array(info.length + 1);
    infoPayload.set(info);
    infoPayload[info.length] = 0x01;

    const okm = await hmacSha256(prk, infoPayload);
    return okm.subarray(0, keyLen);
}

export function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    const len = clean.length;
    const bytes = new Uint8Array(len / 2);
    for (let i = 0; i < len; i += 2) {
        bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    }
    return bytes;
}
