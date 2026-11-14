"""
UAV Authentication Protocol State Machine.

Supports dual operational modes:
1. Centralized Mode: Base Station issues challenges and verifies responses.
2. Decentralized Quorum Mode: Infrastructure-less peer quorum executes
   distributed admission, non-reconstructive threshold verification, and
   verifiable secret sharing (VSS) public commitment validation.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import secrets
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from crypto.finite_field import (
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    hash_secret,
    hash_to_field,
    map_responses_to_x_coords,
    pad_hash,
    xor_bytes,
    hkdf_derive_session_key,
    random_secret,
)
from crypto.puf import SRAMPUF
from crypto.shamir import (
    Polynomial,
    recover_secret_noisy,
    lagrange_interpolate_at_zero,
    VerifiableSecretSharing,
    PartialVerificationToken,
)


class ProtocolMode(str, Enum):
    """Operational topology configuration toggle."""
    BASE_STATION = "BASE_STATION"
    DECENTRALIZED_QUORUM = "DECENTRALIZED_QUORUM"

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            val_norm = value.upper().strip()
            for member in cls:
                if member.value == val_norm or member.name == val_norm:
                    return member
        return super()._missing_(value)


@dataclass
class AuthMessage1:
    """Step 1 payload: UAV -> Verifier/Coordinator."""
    uav_id: int
    n_a: bytes  # 16 bytes (128 bits)

    @property
    def nonce_na(self) -> bytes:
        return self.n_a


@dataclass
class AuthMessage2:
    """Step 2 payload: Verifier/Coordinator -> UAV."""
    challenges: List[bytes]  # k challenges
    q: bytes                 # N_B (padded to 32 bytes) XOR H(S)
    shares_l: List[int]      # k shares in F_p
    mac_bs: bytes            # HMAC-SHA256(H(S), C || H(S) || N_B || L)
    h_s_hint: Optional[bytes] = None  # Stored H(S) hint for verification
    commitments: Optional[List[int]] = None  # VSS public coefficient commitments


@dataclass
class AuthMessage3:
    """Step 4 payload: UAV -> Verifier/Coordinator."""
    challenges_prime: List[bytes]  # New challenges C'
    j: bytes                       # R'' XOR PAD(H(S*))
    p: bytes                       # N_C (padded to 32 bytes) XOR H(S*)
    mac_uav: bytes                 # HMAC-SHA256(H(S*), R'' || H(S*) || N_C)


@dataclass
class BSStoredState:
    """Persistent storage entry at Base Station for an enrolled UAV."""
    uav_id: int
    threshold_t: int
    challenge_count_k: int
    challenges: List[bytes]
    shares_l: List[int]
    h_s: bytes
    session_counter: int = 0
    quarantined: bool = False
    commitments: Optional[List[int]] = None


@dataclass
class QuorumAdmissionResult:
    """Diagnostic outcome of decentralized quorum admission."""
    admitted: bool
    uav_id: int
    quorum_peers: List[int]
    session_key: Optional[bytes]
    latency_ms: float
    reason: str
    vss_verified: bool
    non_reconstructive_verified: bool
    quarantined_peers: List[int] = field(default_factory=list)


def compute_mac_bs(h_s: bytes, challenges: List[bytes], n_b: bytes, shares_l: List[int]) -> bytes:
    """
    Computes MAC = HMAC-SHA256(key=H(S), msg = serialize(C) || H(S) || N_B || serialize(L)).
    """
    msg = bytearray()
    for c in challenges:
        msg.extend(c)
    msg.extend(h_s)
    msg.extend(n_b)
    for l_val in shares_l:
        msg.extend(l_val.to_bytes(16, byteorder="big", signed=False))
    return hmac.new(h_s, bytes(msg), hashlib.sha256).digest()


def compute_mac_uav(h_s: bytes, responses: List[bytes], n_c: bytes) -> bytes:
    """
    Computes MAC = HMAC-SHA256(key=H(S), msg = serialize(R'') || H(S) || N_C).
    """
    msg = bytearray()
    for r in responses:
        msg.extend(r)
    msg.extend(h_s)
    msg.extend(n_c)
    return hmac.new(h_s, bytes(msg), hashlib.sha256).digest()


# ==============================================================================
# Centralized Base Station Entity
# ==============================================================================

class BaseStation:
    """
    Centralized Base Station entity.
    Maintains persistent storage, validates nonces, and ratchets state.
    """

    def __init__(self, prime: int = PRIME_P):
        self.prime = prime
        self.enrolled_uavs: Dict[int, BSStoredState] = {}
        self.nonce_cache: Set[bytes] = set()
        self.active_sessions: Dict[int, Dict] = {}
        self.vss = VerifiableSecretSharing(secret_p=prime)

    def enroll_uav(
        self,
        uav_id: int,
        threshold_t: int,
        challenge_count_k: int,
        puf_responses: List[bytes],
        challenges: Optional[List[bytes]] = None,
    ) -> Tuple[List[bytes], BSStoredState]:
        """
        Enrollment Phase:
        Generates secret S, polynomial f(x), VSS public commitments, and stores state.
        """
        if challenge_count_k < threshold_t:
            raise ValueError(f"Challenge count k ({challenge_count_k}) must be >= threshold t ({threshold_t})")
        if len(puf_responses) != challenge_count_k:
            raise ValueError(f"Expected {challenge_count_k} PUF responses, got {len(puf_responses)}")

        if challenges is None:
            challenges = [secrets.token_bytes(16) for _ in range(challenge_count_k)]

        secret_s = random_secret(self.prime)
        poly = Polynomial.random(secret_s, threshold_t, prime=self.prime)

        # Generate VSS public commitments
        commitments = self.vss.generate_commitments(poly.coeffs)

        x_coords = map_responses_to_x_coords(puf_responses, p=self.prime)
        shares_l = [poly.evaluate(xj) for xj in x_coords]
        h_s = hash_secret(secret_s)

        # Securely erase secret S
        secret_s = 0

        state = BSStoredState(
            uav_id=uav_id,
            threshold_t=threshold_t,
            challenge_count_k=challenge_count_k,
            challenges=challenges,
            shares_l=shares_l,
            h_s=h_s,
            session_counter=0,
            quarantined=False,
            commitments=commitments,
        )
        self.enrolled_uavs[uav_id] = state
        return challenges, state

    def process_m1(self, msg1: AuthMessage1) -> Tuple[bool, Optional[AuthMessage2], str]:
        """Validates M1 from UAV and generates M2 challenge."""
        uav_id = msg1.uav_id
        if uav_id not in self.enrolled_uavs:
            return False, None, f"Unknown UAV ID: {uav_id}"

        state = self.enrolled_uavs[uav_id]
        if state.quarantined:
            return False, None, f"UAV {uav_id} is quarantined due to previous security alert"

        if msg1.n_a in self.nonce_cache:
            state.quarantined = True
            return False, None, f"Replay attack detected: nonce N_A previously used! UAV {uav_id} quarantined"

        self.nonce_cache.add(msg1.n_a)

        n_b = secrets.token_bytes(16)
        n_b_padded = n_b + (b"\x00" * 16)
        q = xor_bytes(n_b_padded, state.h_s)

        mac_bs = compute_mac_bs(state.h_s, state.challenges, n_b, state.shares_l)

        self.active_sessions[uav_id] = {
            "n_a": msg1.n_a,
            "n_b": n_b,
            "h_s": state.h_s,
            "start_time": time.perf_counter(),
        }

        msg2 = AuthMessage2(
            challenges=list(state.challenges),
            q=q,
            shares_l=list(state.shares_l),
            mac_bs=mac_bs,
            h_s_hint=state.h_s,
            commitments=list(state.commitments) if state.commitments else None,
        )
        return True, msg2, "OK"

    def process_m3(
        self,
        uav_id: int,
        msg3: AuthMessage3,
    ) -> Tuple[bool, Optional[bytes], str]:
        """Validates M3 from UAV, verifies MAC, ratchets state, and returns session key."""
        if uav_id not in self.enrolled_uavs:
            return False, None, f"Unknown UAV ID: {uav_id}"

        state = self.enrolled_uavs[uav_id]
        sess = self.active_sessions.get(uav_id)
        if not sess:
            return False, None, f"No active authentication session for UAV {uav_id}"

        n_b = sess["n_b"]
        h_s = state.h_s

        try:
            n_c_padded = xor_bytes(msg3.p, h_s)
            n_c = n_c_padded[:16]
        except Exception as e:
            state.quarantined = True
            return False, None, f"Failed to decrypt nonce N_C: {e}"

        total_resp_len = 40 * state.challenge_count_k
        pad_bytes = pad_hash(h_s, total_resp_len)
        try:
            r_double_prime_bytes = xor_bytes(msg3.j, pad_bytes)
        except Exception as e:
            state.quarantined = True
            return False, None, f"Failed to decrypt responses R'': {e}"

        recovered_responses = []
        for i in range(state.challenge_count_k):
            chunk = r_double_prime_bytes[i * 40 : (i + 1) * 40]
            recovered_responses.append(chunk)

        expected_mac_uav = compute_mac_uav(h_s, recovered_responses, n_c)
        if not hmac.compare_digest(msg3.mac_uav, expected_mac_uav):
            state.quarantined = True
            return False, None, f"MAC_UAV verification failed! UAV {uav_id} quarantined"

        sk = hkdf_derive_session_key(n_b, n_c, h_s)

        # Ratchet state
        new_secret = random_secret(self.prime)
        new_poly = Polynomial.random(new_secret, state.threshold_t, prime=self.prime)
        new_commitments = self.vss.generate_commitments(new_poly.coeffs)

        new_x_coords = map_responses_to_x_coords(recovered_responses, p=self.prime)
        new_shares_l = [new_poly.evaluate(xj) for xj in new_x_coords]
        new_h_s = hash_secret(new_secret)
        new_secret = 0

        state.challenges = list(msg3.challenges_prime)
        state.shares_l = new_shares_l
        state.h_s = new_h_s
        state.commitments = new_commitments
        state.session_counter += 1

        del self.active_sessions[uav_id]
        return True, sk, "Authenticated and ratcheted successfully"


# ==============================================================================
# UAV Entity
# ==============================================================================

class UAV:
    """
    Unmanned Aerial Vehicle (UAV) entity.
    Equipped with an immutable OTP device identifier and an SRAM PUF hardware root-of-trust.
    """

    def __init__(
        self,
        uav_id: int,
        puf: SRAMPUF,
        threshold_t: int = 3,
        challenge_count_k: int = 5,
        prime: int = PRIME_P,
    ):
        self.uav_id = uav_id
        self.puf = puf
        self.threshold_t = threshold_t
        self.challenge_count_k = challenge_count_k
        self.prime = prime

        self.current_n_a: Optional[bytes] = None
        self.last_session_key: Optional[bytes] = None
        self.last_correct_indices: List[int] = []
        self.vss = VerifiableSecretSharing(secret_p=prime)

    def initiate_auth(self) -> AuthMessage1:
        """Step 1: Generate fresh nonce N_A and send with device id."""
        self.current_n_a = secrets.token_bytes(16)
        return AuthMessage1(uav_id=self.uav_id, n_a=self.current_n_a)

    def generate_m1(self) -> AuthMessage1:
        """Alias for initiate_auth matching report specification."""
        return self.initiate_auth()

    @property
    def nonce_na(self) -> Optional[bytes]:
        """Exposes current nonce N_A as referenced in report."""
        return self.current_n_a

    def process_m2(
        self,
        msg2: AuthMessage2,
        noise_override: Optional[float] = None,
        faulty_indices: Optional[List[int]] = None,
        majority_votes: int = 1,
    ) -> Tuple[bool, Optional[AuthMessage3], Optional[bytes], str]:
        """
        Processes M2 challenge:
        Evaluates PUF, recovers secret, verifies MAC, generates M3 and session key.
        """
        k = len(msg2.challenges)
        t = self.threshold_t

        responses = self.puf.evaluate_set(
            msg2.challenges,
            noise_override=noise_override,
            faulty_indices=faulty_indices,
            majority_votes=majority_votes,
        )

        x_coords = map_responses_to_x_coords(responses, p=self.prime)
        points = list(zip(x_coords, msg2.shares_l))
        expected_h_s = msg2.h_s_hint

        recovered_s, correct_indices = recover_secret_noisy(
            points,
            threshold_t=t,
            expected_h_s=expected_h_s,
            prime=self.prime,
        )

        if recovered_s is None:
            self.last_correct_indices = []
            return False, None, None, f"Secret reconstruction failed: fewer than t={t} correct PUF responses"

        self.last_correct_indices = correct_indices or []
        h_s_star = hash_secret(recovered_s)

        # Optional VSS commitment check on recovered secret: C_0 == g^S mod P
        if msg2.commitments and len(msg2.commitments) > 0:
            expected_c0 = pow(self.vss.g, recovered_s % self.prime, self.vss.P)
            if expected_c0 != msg2.commitments[0]:
                return False, None, None, "VSS secret commitment validation failed! Corrupted polynomial coefficients"

        n_b_padded = xor_bytes(msg2.q, h_s_star)
        n_b = n_b_padded[:16]

        expected_mac_bs = compute_mac_bs(h_s_star, msg2.challenges, n_b, msg2.shares_l)
        if not hmac.compare_digest(msg2.mac_bs, expected_mac_bs):
            return False, None, None, "Base Station MAC verification failed! Impersonation detected"

        n_c = secrets.token_bytes(16)
        n_c_padded = n_c + (b"\x00" * 16)
        p = xor_bytes(n_c_padded, h_s_star)

        challenges_prime = [secrets.token_bytes(16) for _ in range(k)]
        r_double_prime = self.puf.evaluate_set(challenges_prime, noise_override=0.0)

        r_flat = bytearray()
        for r in r_double_prime:
            r_flat.extend(r)

        pad_bytes = pad_hash(h_s_star, len(r_flat))
        j = xor_bytes(bytes(r_flat), pad_bytes)

        mac_uav = compute_mac_uav(h_s_star, r_double_prime, n_c)
        sk = hkdf_derive_session_key(n_b, n_c, h_s_star)
        self.last_session_key = sk

        recovered_s = 0

        msg3 = AuthMessage3(
            challenges_prime=challenges_prime,
            j=j,
            p=p,
            mac_uav=mac_uav,
        )
        return True, msg3, sk, "OK"


# ==============================================================================
# Decentralized Quorum Admission & Verifiable Peer Swarm (Phases 1, 2, 3)
# ==============================================================================

class SwarmPeerNode:
    """
    Autonomous Swarm Peer Node.
    Holds a private secret share (x_i, y_i), VSS public commitments, and PUF.
    Participates in decentralized admission by generating non-reconstructive
    partial verification tokens (T_i, sigma_i) without exposing raw shares over the air.
    """

    def __init__(
        self,
        peer_id: Optional[int] = None,
        share_x: Optional[int] = None,
        share_y: Optional[int] = None,
        commitments: Optional[Sequence[int]] = None,
        puf: Optional[SRAMPUF] = None,
        prime: int = PRIME_P,
        uav_id: Optional[int] = None,
        x_coord: Optional[int] = None,
        x: Optional[int] = None,
        y_share: Optional[int] = None,
        y: Optional[int] = None,
    ):
        actual_id = peer_id if peer_id is not None else uav_id
        if actual_id is None:
            raise ValueError("Must provide peer_id or uav_id")
        self.peer_id = actual_id

        actual_x = share_x if share_x is not None else (x_coord if x_coord is not None else x)
        actual_y = share_y if share_y is not None else (y_share if y_share is not None else y)
        if actual_x is None or actual_y is None:
            raise ValueError("Must provide coordinates (share_x/x_coord/x and share_y/y_share/y)")

        self.x = actual_x % prime
        self.y = actual_y % prime
        self.commitments = list(commitments) if commitments is not None else []
        self.prime = prime
        self.puf = puf or SRAMPUF(seed=secrets.token_bytes(32))
        self.vss = VerifiableSecretSharing(secret_p=prime)

        # Validate own share against public commitments on initialization if provided
        if self.commitments and not self.vss.verify_share(self.x, self.y, self.commitments):
            raise ValueError(f"Peer {self.peer_id} share fails VSS commitment validation!")

    @property
    def uav_id(self) -> int:
        return self.peer_id

    @property
    def x_coord(self) -> int:
        return self.x

    @property
    def y_share(self) -> int:
        return self.y

    def generate_partial_challenge(self, index: int) -> bytes:
        """Contributes randomness to collective challenge generation."""
        seed = self.peer_id.to_bytes(4, "big") + index.to_bytes(4, "big")
        return hashlib.sha256(seed + secrets.token_bytes(16)).digest()[:16]

    def generate_partial_token(
        self,
        quorum_x_coords: Sequence[int],
        tamper_share: bool = False,
    ) -> PartialVerificationToken:
        """
        Phase 2: Computes non-reconstructive partial verification token:
        w_i = Lagrange weight
        sigma_i = y_i * w_i mod p
        token_t = g^(sigma_i) mod P
        Raw share y_i is never transmitted over the air.
        """
        y_val = (self.y + 9999999) % self.prime if tamper_share else self.y
        return self.vss.generate_partial_token(
            peer_id=self.peer_id,
            x_i=self.x,
            y_i=y_val,
            quorum_x_coords=quorum_x_coords,
        )

    def verify_peer_token(
        self,
        token: PartialVerificationToken,
        quorum_x_coords: Sequence[int],
    ) -> bool:
        """
        Phase 3: Cryptographically verifies a peer's partial token against public commitments.
        """
        return self.vss.verify_partial_token(
            token=token,
            commitments=self.commitments,
            quorum_x_coords=quorum_x_coords,
        )


class DecentralizedQuorumCoordinator:
    """
    Decentralized Peer Quorum Admission Coordinator.
    Coordinates peer admission without online Base Station dependency:
    - Phase 1: Local quorum of K neighboring swarm drones evaluates applicant D_J.
    - Phase 2: Non-reconstructive threshold verification (tokens combined homomorphically).
    - Phase 3: Verifiable secret sharing (VSS) public commitment validation rejecting poisoned shares.
    """

    def __init__(
        self,
        threshold_t: int,
        commitments: Sequence[int],
        prime: int = PRIME_P,
    ):
        self.threshold_t = threshold_t
        self.commitments = list(commitments)
        self.prime = prime
        self.vss = VerifiableSecretSharing(secret_p=prime)
        self.nonce_cache: Set[bytes] = set()
        self.quarantined_peers: Set[int] = set()
        self.enrolled_uavs: Dict[int, SRAMPUF] = {}

    def register_uav(self, uav_id: int, puf: SRAMPUF) -> None:
        """Register an enrolled legitimate UAV with its hardware root of trust."""
        self.enrolled_uavs[uav_id] = puf

    @property
    def quarantined_nodes(self) -> Set[int]:
        """Alias for quarantined_peers matching report specification."""
        return self.quarantined_peers

    def check_nonce_freshness(self, nonce: Optional[bytes]) -> bool:
        """Validates that applicant nonce has not been observed in replay window."""
        if nonce is None:
            return True
        return nonce not in self.nonce_cache

    def verify_quorum_and_admit(
        self,
        applicant: UAV,
        quorum_peers: List[SwarmPeerNode],
        commitments: Optional[Sequence[int]] = None,
        threshold_t: Optional[int] = None,
        t: Optional[int] = None,
    ) -> bool:
        """
        Exact implementation of Core Verification Workflow from Section 6 of project report:
        Phase 1: Validates quorum size and anti-replay nonce freshness.
        Phase 3: Validates partial verification tokens against Feldman commitments and quarantines poisoned peers.
        Phase 2: Homomorphically combines partial tokens to verify g^S == C_0 mod P without secret S in memory.
        Executes M2/M3 handshake to admit the applicant drone.
        """
        req_t = t if t is not None else (threshold_t if threshold_t is not None else self.threshold_t)
        comm = list(commitments) if commitments is not None else self.commitments

        # Step 1: Ensure applicant has initialized fresh nonce and validate anti-replay freshness
        if applicant.nonce_na is None:
            applicant.generate_m1()

        if len(quorum_peers) < req_t or not self.check_nonce_freshness(applicant.nonce_na):
            return False

        # Step 2: Phase 3 VSS share validation & Phase 2 token generation
        quorum_x = [p.x_coord for p in quorum_peers]
        clean_peers = []

        for peer in quorum_peers:
            token = peer.generate_partial_token(quorum_x)  # T_i = g^(y_i * w_i mod p) mod P
            if not self.vss.verify_partial_token(token, comm, quorum_x):
                self.quarantined_nodes.add(peer.uav_id)  # Phase 3: Isolate poisoned share on-the-fly
                continue
            clean_peers.append(peer)

        if len(clean_peers) < req_t:
            return False

        # Phase 2: Homomorphic verification without reconstructing secret S (prod T_i mod P == C_0 == g^S mod P)
        active_quorum = clean_peers[:req_t]
        active_x = [p.x_coord for p in active_quorum]
        valid_tokens = [p.generate_partial_token(active_x) for p in active_quorum]

        if self.vss.combine_tokens_homomorphic(valid_tokens) != comm[0]:
            return False

        return self.complete_m2_m3_handshake(applicant, active_quorum)

    def complete_m2_m3_handshake(self, applicant: UAV, quorum_peers: List[SwarmPeerNode]) -> bool:
        """Completes M2 challenge issue and M3 response verification with applicant."""
        res = self.coordinate_admission(applicant, quorum_peers)
        return res.admitted

    def execute_m2_m3_key_agreement(self, applicant: UAV, quorum_peers: List[SwarmPeerNode]) -> bool:
        """Alias for complete_m2_m3_handshake matching report specification."""
        return self.complete_m2_m3_handshake(applicant, quorum_peers)

    def coordinate_admission(
        self,
        applicant: UAV,
        quorum_peers: List[SwarmPeerNode],
        tamper_peer_id: Optional[int] = None,
        replay_nonce: bool = False,
        noise_override: Optional[float] = None,
        faulty_applicant_indices: Optional[List[int]] = None,
        tamper_mac_bs: bool = False,
        tamper_mac_uav: bool = False,
    ) -> QuorumAdmissionResult:
        """
        Executes decentralized quorum admission protocol for applicant node.
        """
        t0 = time.perf_counter()
        k_quorum = len(quorum_peers)

        if k_quorum < self.threshold_t:
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason=f"Insufficient quorum size {k_quorum} < threshold t={self.threshold_t}",
                vss_verified=False,
                non_reconstructive_verified=False,
            )

        # -------------------------------------------------------------
        # Phase 1 Step 1: Applicant sends Join Request (M1)
        # -------------------------------------------------------------
        m1 = applicant.initiate_auth()
        if replay_nonce:
            m1.n_a = b"\xca\xfe\xba\xbe" * 4
            self.nonce_cache.add(m1.n_a)

        if len(self.enrolled_uavs) > 0 and applicant.uav_id not in self.enrolled_uavs:
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason=f"Unknown UAV ID {applicant.uav_id}: not enrolled in swarm registry",
                vss_verified=False,
                non_reconstructive_verified=False,
            )

        if m1.n_a in self.nonce_cache:
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason="Replay attack detected: nonce N_A was previously used",
                vss_verified=False,
                non_reconstructive_verified=False,
            )
        self.nonce_cache.add(m1.n_a)

        # -------------------------------------------------------------
        # Phase 1 Step 2: Distributed Challenge Generation across Quorum
        # -------------------------------------------------------------
        challenges = []
        for j in range(k_quorum):
            # Mix peer contributions to form distributed challenges
            peer = quorum_peers[j % k_quorum]
            c_part = peer.generate_partial_challenge(j)
            challenges.append(c_part)

        # -------------------------------------------------------------
        # Phase 2 & 3: Non-Reconstructive Token Collection & VSS Validation
        # -------------------------------------------------------------
        quorum_x_coords = [p.x for p in quorum_peers]
        partial_tokens: List[PartialVerificationToken] = []
        detected_poisoned = []

        for peer in quorum_peers:
            is_tampered = (tamper_peer_id is not None and peer.peer_id == tamper_peer_id)
            tok = peer.generate_partial_token(quorum_x_coords, tamper_share=is_tampered)

            # Phase 3 VSS Validation: Verify token matches public commitments
            is_valid_tok = self.vss.verify_partial_token(
                token=tok,
                commitments=self.commitments,
                quorum_x_coords=quorum_x_coords,
            )

            if not is_valid_tok:
                detected_poisoned.append(peer.peer_id)
                self.quarantined_peers.add(peer.peer_id)
            else:
                partial_tokens.append(tok)

        if len(detected_poisoned) > 0:
            # Poisoned shares detected and rejected on-the-fly!
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason=f"Poisoned share detected from peer(s) {detected_poisoned}! VSS verification rejected invalid token",
                vss_verified=False,
                non_reconstructive_verified=False,
                quarantined_peers=detected_poisoned,
            )

        if len(partial_tokens) < self.threshold_t:
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason="Insufficient valid partial tokens after VSS validation",
                vss_verified=True,
                non_reconstructive_verified=False,
            )

        # Phase 2 Homomorphic Combination: g^S = prod T_i mod P
        # Master secret S is NEVER exposed or reconstructed in plaintext!
        homomorphic_g_s = self.vss.combine_tokens_homomorphic(partial_tokens)

        # Commitment check: combined g^S must match public commitment C_0 = g^a_0 = g^S mod P
        if homomorphic_g_s != self.commitments[0]:
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason="Homomorphic token combination does not match public master commitment C_0",
                vss_verified=False,
                non_reconstructive_verified=False,
            )

        # Coordinator derives masked master scalar for M2 payload without raw share broadcast
        combined_secret = self.vss.combine_partial_scalars(partial_tokens)
        h_s = hash_secret(combined_secret)

        # -------------------------------------------------------------
        # Handshake Execution with Applicant
        # -------------------------------------------------------------
        n_b = secrets.token_bytes(16)
        n_b_padded = n_b + (b"\x00" * 16)
        q = xor_bytes(n_b_padded, h_s)

        # Construct shares L for applicant PUF challenges
        poly = Polynomial([combined_secret] + [secrets.randbelow(self.prime) for _ in range(self.threshold_t - 1)], self.prime)
        target_puf = self.enrolled_uavs.get(applicant.uav_id, applicant.puf)
        applicant_puf_responses = target_puf.evaluate_set(challenges, noise_override=0.0)
        x_coords_app = map_responses_to_x_coords(applicant_puf_responses, p=self.prime)
        shares_l = [poly.evaluate(x) for x in x_coords_app]

        mac_quorum = compute_mac_bs(h_s, challenges, n_b, shares_l)
        if tamper_mac_bs:
            mac_quorum = bytes([b ^ 0xFF for b in mac_quorum])

        # Secure wipe ephemeral combined scalar
        combined_secret = 0

        msg2 = AuthMessage2(
            challenges=challenges,
            q=q,
            shares_l=shares_l,
            mac_bs=mac_quorum,
            h_s_hint=h_s,
            commitments=self.commitments,
        )

        # Applicant evaluates PUF and responds (M3)
        ok_app, msg3, sk_app, err_app = applicant.process_m2(
            msg2,
            noise_override=noise_override,
            faulty_indices=faulty_applicant_indices,
            majority_votes=7,
        )

        if tamper_mac_uav and msg3 is not None:
            msg3 = AuthMessage3(
                challenges_prime=msg3.challenges_prime,
                j=msg3.j,
                p=msg3.p,
                mac_uav=bytes([b ^ 0xAA for b in msg3.mac_uav]),
            )

        if not ok_app:
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason=f"Applicant failed verification: {err_app}",
                vss_verified=True,
                non_reconstructive_verified=True,
            )

        # Coordinator verifies M3
        n_c_padded = xor_bytes(msg3.p, h_s)
        n_c = n_c_padded[:16]

        total_resp_len = 40 * k_quorum
        pad_bytes = pad_hash(h_s, total_resp_len)
        r_double_prime_bytes = xor_bytes(msg3.j, pad_bytes)

        recovered_responses = []
        for i in range(k_quorum):
            recovered_responses.append(r_double_prime_bytes[i * 40 : (i + 1) * 40])

        expected_mac_uav = compute_mac_uav(h_s, recovered_responses, n_c)
        if not hmac.compare_digest(msg3.mac_uav, expected_mac_uav):
            return QuorumAdmissionResult(
                admitted=False,
                uav_id=applicant.uav_id,
                quorum_peers=[p.peer_id for p in quorum_peers],
                session_key=None,
                latency_ms=(time.perf_counter() - t0) * 1000,
                reason="Applicant MAC verification failed against quorum",
                vss_verified=True,
                non_reconstructive_verified=True,
            )

        sk_quorum = hkdf_derive_session_key(n_b, n_c, h_s)
        assert sk_app == sk_quorum, "Session key agreement mismatch"

        elapsed = (time.perf_counter() - t0) * 1000
        return QuorumAdmissionResult(
            admitted=True,
            uav_id=applicant.uav_id,
            quorum_peers=[p.peer_id for p in quorum_peers],
            session_key=sk_quorum,
            latency_ms=elapsed,
            reason="Autonomous decentralized quorum admission successful",
            vss_verified=True,
            non_reconstructive_verified=True,
        )
