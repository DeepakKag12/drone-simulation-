"""
Threshold Secret Sharing and Verifiable Secret Sharing Engine.

Mathematical formulation:
- Polynomial: f(x) = S + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1} (mod p)
- Degree: t - 1 (requiring exactly t points to uniquely interpolate f(0) = S)
- Fast O(t) reconstruction at x=0 using precomputed barycentric weights
- Verifiable Secret Sharing with public coefficient commitments in Z_P*
- Non-reconstructive threshold partial verification tokens
- Berlekamp-Welch error correction and combinatorial subset recovery
"""

from dataclasses import dataclass
import itertools
from typing import Dict, List, Optional, Sequence, Tuple

from crypto.finite_field import (
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    mod_inverse,
    field_add,
    field_sub,
    field_mul,
    random_field_element,
    hash_secret,
)


@dataclass(frozen=True)
class SharePoint:
    """Represents a coordinate pair (x_i, y_i) in F_p."""
    index: int
    x: int
    y: int

    def as_tuple(self) -> Tuple[int, int]:
        return (self.x, self.y)


@dataclass(frozen=True)
class PartialVerificationToken:
    """
    Non-reconstructive partial token computed locally by a quorum peer.
    sigma_i = y_i * w_i mod p
    token_t = g^(y_i * w_i) mod P
    """
    peer_id: int
    x: int
    sigma: int
    token_t: int


class Polynomial:
    """Polynomial over finite field F_p."""

    def __init__(self, coefficients: Sequence[int], prime: int = PRIME_P):
        """
        Coefficients [a0, a1, ..., a_{t-1}] where a0 is constant term f(0) = S.
        Degree is len(coefficients) - 1.
        """
        self.prime = prime
        self.coeffs = [c % prime for c in coefficients]
        while len(self.coeffs) > 1 and self.coeffs[-1] == 0:
            self.coeffs.pop()

    @property
    def degree(self) -> int:
        return len(self.coeffs) - 1

    @property
    def coefficients(self) -> List[int]:
        return list(self.coeffs)

    def evaluate(self, x: int) -> int:
        """Horner's method for polynomial evaluation at x mod p."""
        p = self.prime
        x = x % p
        result = 0
        for coeff in reversed(self.coeffs):
            result = (result * x + coeff) % p
        return result

    @classmethod
    def random(cls, secret: int, threshold_t: int, prime: int = PRIME_P) -> "Polynomial":
        """
        Generate random polynomial of degree t-1 with constant term secret:
        f(x) = secret + a1*x + ... + a_{t-1}*x^{t-1} mod p.
        """
        if threshold_t < 1:
            raise ValueError(f"Threshold t must be >= 1, got {threshold_t}")

        coeffs = [secret % prime]
        for _ in range(threshold_t - 1):
            coeffs.append(random_field_element(prime))
        return cls(coeffs, prime=prime)


class BarycentricInterpolator:
    """
    Computes barycentric weights for t distinct x-coordinates to evaluate
    Lagrange interpolation at x = 0 in O(t) multiplications:
    S = sum_{i=0}^{t-1} y_i * w_i (mod p)
    where w_i = prod_{j != i} (-x_j) / (x_i - x_j) (mod p).
    """

    def __init__(self, x_coords: Sequence[int], prime: int = PRIME_P):
        self.prime = prime
        self.x_coords = [x % prime for x in x_coords]
        self.t = len(self.x_coords)
        if len(set(self.x_coords)) != self.t:
            raise ValueError("All x-coordinates must be distinct for interpolation")
        self.weights: List[int] = self._compute_weights()

    def _compute_weights(self) -> List[int]:
        t = self.t
        p = self.prime
        xs = self.x_coords

        if t == 0:
            return []
        if t == 1:
            return [1]

        # Numerator: prod_{j != i} (-x_j) mod p using prefix and suffix arrays
        prefix = [1] * (t + 1)
        for i in range(t):
            term = (-xs[i]) % p
            prefix[i + 1] = (prefix[i] * term) % p

        suffix = [1] * (t + 1)
        for i in range(t - 1, -1, -1):
            term = (-xs[i]) % p
            suffix[i] = (suffix[i + 1] * term) % p

        weights = []
        for i in range(t):
            num = (prefix[i] * suffix[i + 1]) % p

            # Denominator: prod_{j != i} (x_i - x_j) mod p
            xi = xs[i]
            den = 1
            for j in range(t):
                if i != j:
                    diff = (xi - xs[j]) % p
                    den = (den * diff) % p

            inv_den = mod_inverse(den, p)
            wi = (num * inv_den) % p
            weights.append(wi)

        return weights

    def reconstruct(self, y_values: Sequence[int]) -> int:
        """Evaluate f(0) in O(t) time."""
        if len(y_values) != self.t:
            raise ValueError(f"Expected {self.t} y-values, got {len(y_values)}")

        p = self.prime
        secret = 0
        for yi, wi in zip(y_values, self.weights):
            term = (yi % p * wi) % p
            secret = (secret + term) % p
        return secret


def lagrange_interpolate_at_zero(points: Sequence[Tuple[int, int]], prime: int = PRIME_P) -> int:
    """
    Interpolate secret S = f(0) from a set of points (x_i, y_i) over F_p.
    """
    xs = [pt[0] for pt in points]
    ys = [pt[1] for pt in points]
    interpolator = BarycentricInterpolator(xs, prime=prime)
    return interpolator.reconstruct(ys)


# ==============================================================================
# Verifiable Secret Sharing (VSS) & Non-Reconstructive Token Operations
# ==============================================================================

class VerifiableSecretSharing:
    """
    Public commitment engine for share verification and non-reconstructive
    threshold verification without plaintext secret exposure.
    """

    def __init__(
        self,
        generator: int = COMMITMENT_GENERATOR_G,
        commitment_p: int = COMMITMENT_PRIME_P,
        secret_p: int = PRIME_P,
    ):
        self.g = generator
        self.P = commitment_p
        self.p = secret_p

    def generate_commitments(self, coefficients: Sequence[int]) -> List[int]:
        """
        Compute public coefficient commitments: C_j = g^(a_j) mod P.
        """
        return [pow(self.g, a % self.p, self.P) for a in coefficients]

    def create_polynomial_and_commitments(self, secret: int, threshold_t: int) -> Tuple[Polynomial, List[int]]:
        """
        Generate random polynomial with secret as constant term and corresponding public commitments.
        """
        poly = Polynomial.random(secret, threshold_t=threshold_t, prime=self.p)
        commitments = self.generate_commitments(poly.coefficients)
        return poly, commitments

    def verify_share(self, x: int, y: int, commitments: Sequence[int]) -> bool:
        """
        Verify share (x, y) against public commitments:
        g^y == prod_{j=0}^{t-1} (C_j)^(x^j mod p) (mod P)
        """
        x = x % self.p
        y = y % self.p

        lhs = pow(self.g, y, self.P)

        rhs = 1
        x_pow = 1
        for c_j in commitments:
            term = pow(c_j, x_pow, self.P)
            rhs = (rhs * term) % self.P
            x_pow = (x_pow * x) % self.p

        return lhs == rhs

    def compute_lagrange_weight(self, target_x: int, quorum_x_coords: Sequence[int]) -> int:
        """
        Compute Lagrange weight w_i = prod_{j != i} (-x_j) / (x_i - x_j) mod p
        for target_x among the given quorum coordinates.
        """
        p = self.p
        target_x = target_x % p
        num = 1
        den = 1
        for xj in quorum_x_coords:
            xj = xj % p
            if xj != target_x:
                num = (num * (-xj)) % p
                den = (den * (target_x - xj)) % p

        inv_den = mod_inverse(den, p)
        return (num * inv_den) % p

    def generate_partial_token(
        self,
        peer_id: int,
        x_i: int,
        y_i: int,
        quorum_x_coords: Sequence[int],
    ) -> PartialVerificationToken:
        """
        Compute non-reconstructive partial verification token:
        w_i = Lagrange weight at x=0
        sigma_i = y_i * w_i mod p
        token_t = g^(sigma_i) mod P
        """
        w_i = self.compute_lagrange_weight(x_i, quorum_x_coords)
        sigma_i = (y_i * w_i) % self.p
        token_t = pow(self.g, sigma_i, self.P)
        return PartialVerificationToken(
            peer_id=peer_id,
            x=x_i,
            sigma=sigma_i,
            token_t=token_t,
        )

    def verify_partial_token(
        self,
        token: PartialVerificationToken,
        commitments: Sequence[int],
        quorum_x_coords: Sequence[int],
    ) -> bool:
        """
        Verify that partial token T_i corresponds to a valid share on the polynomial:
        expected_g_y = prod (C_j)^(x_i^j) mod P
        expected_T_i = (expected_g_y)^w_i mod P == token.token_t
        """
        w_i = self.compute_lagrange_weight(token.x, quorum_x_coords)

        expected_g_y = 1
        x_pow = 1
        for c_j in commitments:
            term = pow(c_j, x_pow, self.P)
            expected_g_y = (expected_g_y * term) % self.P
            x_pow = (x_pow * token.x) % self.p

        expected_token = pow(expected_g_y, w_i, self.P)
        return expected_token == token.token_t

    def combine_tokens_homomorphic(self, tokens: Sequence[PartialVerificationToken]) -> int:
        """
        Combine partial tokens without plaintext secret reconstruction:
        g^S = prod_{i in Q} T_i mod P
        """
        combined = 1
        for tok in tokens:
            combined = (combined * tok.token_t) % self.P
        return combined

    def combine_partial_scalars(self, tokens: Sequence[PartialVerificationToken]) -> int:
        """
        Sum of masked partial scalars: S = sum sigma_i mod p.
        """
        s = 0
        for tok in tokens:
            s = (s + tok.sigma) % self.p
        return s


# ==============================================================================
# Polynomial Algebra Helpers for Error Decoding
# ==============================================================================

def poly_divmod(dividend: List[int], divisor: List[int], prime: int = PRIME_P) -> Tuple[List[int], List[int]]:
    """Polynomial division in F_p[x]. Returns (quotient, remainder)."""
    p = prime
    dividend = [c % p for c in dividend]
    while len(dividend) > 1 and dividend[-1] == 0:
        dividend.pop()
    divisor = [c % p for c in divisor]
    while len(divisor) > 1 and divisor[-1] == 0:
        divisor.pop()

    if len(divisor) == 1 and divisor[0] == 0:
        raise ZeroDivisionError("Polynomial division by zero")

    quotient = [0] * max(1, len(dividend) - len(divisor) + 1)
    remainder = list(dividend)

    inv_lead = mod_inverse(divisor[-1], p)

    while len(remainder) >= len(divisor) and not (len(remainder) == 1 and remainder[0] == 0):
        deg_diff = len(remainder) - len(divisor)
        factor = (remainder[-1] * inv_lead) % p
        quotient[deg_diff] = factor

        for i, div_c in enumerate(divisor):
            pos = deg_diff + i
            remainder[pos] = (remainder[pos] - factor * div_c) % p

        while len(remainder) > 1 and remainder[-1] == 0:
            remainder.pop()

    return quotient, remainder


def solve_linear_system(matrix: List[List[int]], vector: List[int], prime: int = PRIME_P) -> Optional[List[int]]:
    """
    Solves A * x = b over F_p using Gaussian elimination.
    Matrix is M x N. Returns solution vector x of length N, or None if inconsistent.
    """
    p = prime
    m = len(matrix)
    n = len(matrix[0]) if m > 0 else 0
    if m == 0 or n == 0:
        return None

    aug = [list(matrix[r]) + [vector[r] % p] for r in range(m)]

    lead = 0
    pivot_cols = []
    for r in range(m):
        if lead >= n:
            break
        i = r
        while i < m and aug[i][lead] == 0:
            i += 1
        if i == m:
            lead += 1
            continue

        aug[r], aug[i] = aug[i], aug[r]
        pivot_val = aug[r][lead]
        inv_pivot = mod_inverse(pivot_val, p)
        for c in range(lead, n + 1):
            aug[r][c] = (aug[r][c] * inv_pivot) % p

        for other_r in range(m):
            if other_r != r and aug[other_r][lead] != 0:
                factor = aug[other_r][lead]
                for c in range(lead, n + 1):
                    aug[other_r][c] = (aug[other_r][c] - factor * aug[r][c]) % p

        pivot_cols.append((r, lead))
        lead += 1

    for r in range(m):
        all_zeros = all(aug[r][c] == 0 for c in range(n))
        if all_zeros and aug[r][n] != 0:
            return None

    solution = [0] * n
    for r, col in reversed(pivot_cols):
        val = aug[r][n]
        for c in range(col + 1, n):
            val = (val - aug[r][c] * solution[c]) % p
        solution[col] = (val % p + p) % p

    return solution


def berlekamp_welch_decode(
    points: Sequence[Tuple[int, int]],
    threshold_t: int,
    prime: int = PRIME_P,
) -> Optional[int]:
    """
    Reed-Solomon Decoder.
    Given k noisy points (x_i, y_i), finds polynomial f(x) of degree <= t-1
    when number of errors e <= floor((k - t) / 2).
    Returns recovered secret f(0), or None if errors exceed decoding radius.
    """
    k = len(points)
    p = prime
    if k < threshold_t:
        return None

    max_errors = (k - threshold_t) // 2
    if max_errors < 1:
        xs = [pt[0] for pt in points[:threshold_t]]
        ys = [pt[1] for pt in points[:threshold_t]]
        return BarycentricInterpolator(xs, prime).reconstruct(ys)

    for e in range(max_errors, 0, -1):
        num_q = threshold_t + e
        num_e = e

        matrix = []
        vector = []
        for xi, yi in points:
            row = []
            x_pow = 1
            for _ in range(num_q):
                row.append(x_pow)
                x_pow = (x_pow * xi) % p

            x_pow = 1
            neg_yi = (-yi) % p
            for _ in range(num_e):
                row.append((neg_yi * x_pow) % p)
                x_pow = (x_pow * xi) % p

            matrix.append(row)
            rhs = (yi * pow(xi, e, p)) % p
            vector.append(rhs)

        sol = solve_linear_system(matrix, vector, prime=p)
        if sol is None:
            continue

        q_coeffs = sol[:num_q]
        e_coeffs = sol[num_q:] + [1]

        try:
            quotient, remainder = poly_divmod(q_coeffs, e_coeffs, prime=p)
        except Exception:
            continue

        if all(r == 0 for r in remainder):
            poly = Polynomial(quotient, prime=p)
            if poly.degree <= threshold_t - 1:
                matches = sum(1 for xi, yi in points if poly.evaluate(xi) == yi % p)
                if matches >= threshold_t:
                    return poly.evaluate(0)

    xs = [pt[0] for pt in points[:threshold_t]]
    ys = [pt[1] for pt in points[:threshold_t]]
    try:
        return BarycentricInterpolator(xs, prime).reconstruct(ys)
    except Exception:
        return None


def recover_secret_noisy(
    points: Sequence[Tuple[int, int]],
    threshold_t: int,
    expected_h_s: bytes,
    prime: int = PRIME_P,
    max_subsets: int = 5000,
) -> Tuple[Optional[int], Optional[List[int]]]:
    """
    Recover secret S* from k noisy points (x_j, L_j) such that SHA256(S*) == expected_h_s.
    Tolerates up to (k - t) faulty responses via decoding and subset search.
    """
    k = len(points)
    if k < threshold_t:
        return None, None

    # Step 1: Attempt fast decoder
    bw_secret = berlekamp_welch_decode(points, threshold_t, prime=prime)
    if bw_secret is not None:
        if hash_secret(bw_secret) == expected_h_s:
            for subset in itertools.combinations(range(k), threshold_t):
                sub_pts = [points[i] for i in subset]
                if lagrange_interpolate_at_zero(sub_pts, prime) == bw_secret:
                    correct = list(subset)
                    for other_idx in range(k):
                        if other_idx not in subset:
                            test_sub = [points[other_idx]] + sub_pts[1:]
                            if lagrange_interpolate_at_zero(test_sub, prime) == bw_secret:
                                correct.append(other_idx)
                    return bw_secret, sorted(list(set(correct)))
            return bw_secret, list(range(threshold_t))

    # Step 2: Combinatorial t-subset search
    all_indices = list(range(k))
    subset_count = 0

    for subset in itertools.combinations(all_indices, threshold_t):
        subset_count += 1
        if subset_count > max_subsets:
            break

        cand_pts = [points[i] for i in subset]
        try:
            cand_s = lagrange_interpolate_at_zero(cand_pts, prime)
        except Exception:
            continue

        if hash_secret(cand_s) == expected_h_s:
            correct_set = set(subset)
            sub_pts = cand_pts
            for other_i in range(k):
                if other_i not in correct_set:
                    test_sub = [points[other_i]] + sub_pts[1:]
                    try:
                        if lagrange_interpolate_at_zero(test_sub, prime) == cand_s:
                            correct_set.add(other_i)
                    except Exception:
                        pass
            return cand_s, sorted(list(correct_set))

    return None, None
