import math
import random
import time
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional
import os

# Windows stability fix for Intel GPU / OpenMP crashes
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
os.environ["OMP_NUM_THREADS"] = "1"

import pybullet as p
import pybullet_data


# =========================
# Shamir Secret Sharing Authentication Module
# =========================

class ShamirSecretSharing:
    """
    Implements (K,N) threshold secret sharing using polynomial interpolation
    over a finite field (mod prime).
    """
    
    PRIME = 2**127 - 1  # Large Mersenne prime for finite field arithmetic
    
    def __init__(self):
        self.weights: List[int] = []
        self.x_coords: List[int] = []
        
    @staticmethod
    def _mod_inverse(a: int, p: int) -> int:
        """Compute modular multiplicative inverse using extended Euclidean algorithm."""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            return gcd, y1 - (b // a) * x1, x1
        _, x, _ = extended_gcd(a % p, p)
        return (x % p + p) % p
        
    def precompute_weights(self, x_coords: List[int], prime: int) -> List[int]:
        """
        Precomputes Lagrange (barycentric) weights for a given set of x-coordinates.
        Instead of O(K^2) nested loops during *every* reconstruction,
        preprocessing is done ONCE, enabling strict O(K) reconstruction.
        """
        k = len(x_coords)
        weights = []
        
        # Precompute numerator prefix and suffix products -> O(K)
        prefix = [1] * (k + 1)
        for i in range(k):
            prefix[i+1] = (prefix[i] * (-x_coords[i])) % prime
            
        suffix = [1] * (k + 1)
        for i in range(k - 1, -1, -1):
            suffix[i] = (suffix[i+1] * (-x_coords[i])) % prime
        
        for i in range(k):
            xi = x_coords[i]
            numerator = (prefix[i] * suffix[i+1]) % prime
            
            denominator = 1
            for j in range(k):
                if i != j:
                    denominator = (denominator * (xi - x_coords[j])) % prime
                    
            lagrange = (numerator * self._mod_inverse(denominator, prime)) % prime
            weights.append(lagrange)
            
        self.weights = weights
        self.x_coords = x_coords
        return weights
    
    @staticmethod
    def generate_shares(secret: int, k: int, n: int) -> List[Tuple[int, int]]:
        """
        Split a secret into n shares where any k shares can reconstruct it.
        Returns list of (x, y) tuples representing share points.
        """
        if k > n:
            raise ValueError("Threshold k cannot exceed total shares n")
        
        # Generate random polynomial coefficients: a_0 = secret, a_1..a_{k-1} random
        coefficients = [secret] + [secrets.randbelow(ShamirSecretSharing.PRIME) for _ in range(k - 1)]
        
        shares = []
        for x in range(1, n + 1):
            # Evaluate polynomial at point x
            y = sum(coef * pow(x, power, ShamirSecretSharing.PRIME) 
                    for power, coef in enumerate(coefficients)) % ShamirSecretSharing.PRIME
            shares.append((x, y))
        
        return shares
    
    @staticmethod
    def reconstruct_secret_fast(shares: List[Tuple[int, int]], weights: List[int], prime: int) -> int:
        """
        Strict O(K) reconstruction using precomputed weights.
        """
        secret = 0
        for (xi, yi), wi in zip(shares, weights):
            secret = (secret + yi * wi) % prime
        return secret


class DroneCredentials:
    """
    Simulates asymmetric key pair and certificate for a drone.
    In production, use proper cryptographic libraries (e.g., cryptography.io).
    """
    
    def __init__(self, drone_id: int):
        self.drone_id = drone_id
        # Simulated private/public key (in real system, use RSA/ECDSA)
        self.private_key = secrets.token_hex(32)
        self.public_key = hashlib.sha256(self.private_key.encode()).hexdigest()
        # Simulated certificate (includes drone_id, public_key, issuer signature)
        self.certificate = self._generate_certificate()
        
    def _generate_certificate(self) -> Dict:
        """Generate a simulated X.509-like certificate."""
        cert_data = f"{self.drone_id}:{self.public_key}"
        issuer_signature = hashlib.sha256(f"CA_SIGNED:{cert_data}".encode()).hexdigest()
        return {
            "drone_id": self.drone_id,
            "public_key": self.public_key,
            "issuer": "SWARM_CA",
            "issuer_signature": issuer_signature,
            "valid_from": time.time(),
            "valid_until": time.time() + 365 * 24 * 3600  # 1 year validity
        }
    
    def sign(self, message: str) -> str:
        """Sign a message using the drone's private key (simulated HMAC)."""
        return hashlib.sha256(f"{self.private_key}:{message}".encode()).hexdigest()
    
    @staticmethod
    def verify_signature(public_key: str, message: str, signature: str, 
                         private_key: str = None) -> bool:
        """
        Verify a signature. In simulation, we need the private key to verify.
        In production, use proper asymmetric verification.
        """
        if private_key is None:
            return False
        expected = hashlib.sha256(f"{private_key}:{message}".encode()).hexdigest()
        return secrets.compare_digest(signature, expected)


class JoinRequest:
    """Encapsulates a JOIN_REQUEST message from a joining drone."""
    
    def __init__(self, drone_id: int, certificate: Dict, nonce: str, 
                 signature: str, timestamp: float):
        self.drone_id = drone_id
        self.certificate = certificate
        self.nonce = nonce
        self.signature = signature  # Signature over (drone_id || nonce || timestamp)
        self.timestamp = timestamp


class ChallengeResponse:
    """Encapsulates the challenge-response from a joining drone."""
    
    def __init__(self, drone_id: int, challenge: str, response_signature: str):
        self.drone_id = drone_id
        self.challenge = challenge
        self.response_signature = response_signature


class ShamirAuthenticationModule:
    """
    Authentication module using Shamir Secret Sharing for secure drone admission.
    
    Flow:
    1. Receive JOIN_REQUEST with Drone_ID, certificate, nonce, and signature
    2. Perform preliminary validation (signature, timestamp, blacklist)
    3. Leader selects K trusted drones to reconstruct the master secret
    4. Generate challenge H(secret || Drone_ID || nonce)
    5. Verify signed response from joining drone
    6. On success → allow join; On failure → reject and blacklist
    """
    
    AUTH_TIMEOUT = 10.0  # Seconds to complete authentication
    TIMESTAMP_TOLERANCE = 60.0  # Max allowed timestamp drift in seconds
    
    def __init__(self, k_threshold: int = 3, master_secret: int = None):
        """
        Initialize the authentication module.
        
        Args:
            k_threshold: Minimum shares needed to reconstruct secret
            master_secret: The master authentication secret (generated if None)
        """
        self.k_threshold = k_threshold
        self.master_secret = master_secret or secrets.randbelow(ShamirSecretSharing.PRIME)
        
        # Drone shares: drone_id -> (x, y) share tuple
        self.drone_shares: Dict[int, Tuple[int, int]] = {}
        
        # Drone credentials storage (for simulation)
        self.drone_credentials: Dict[int, DroneCredentials] = {}
        
        # Pending authentication sessions: drone_id -> session data
        self.pending_auth: Dict[int, Dict] = {}
        
        # Blacklist of rejected drone IDs
        self.blacklist: set = set()
        
        # Trusted CA public key (simulated)
        self.ca_public_key = "SWARM_CA_PUBLIC_KEY"
        
        self.sss_engine = ShamirSecretSharing()
        
        print(f"[AUTH] ShamirAuthenticationModule initialized with K={k_threshold}")
    
    def distribute_shares(self, drone_ids: List[int]) -> None:
        """
        Distribute secret shares to all drones in the swarm.
        Called when swarm is initialized or when membership changes.
        """
        n = len(drone_ids)
        if n == 0:
            return
            
        # Adjust k if we have fewer drones than threshold
        effective_k = min(self.k_threshold, n)
        
        shares = ShamirSecretSharing.generate_shares(self.master_secret, effective_k, n)
        
        self.drone_shares.clear()
        for drone_id, share in zip(sorted(drone_ids), shares):
            self.drone_shares[drone_id] = share
            # Generate credentials for each drone
            if drone_id not in self.drone_credentials:
                self.drone_credentials[drone_id] = DroneCredentials(drone_id)
        
        print(f"\n[SHARES] {'='*50}")
        print(f"[SHARES] Shamir Secret Shares Distributed")
        print(f"[SHARES] {'='*50}")
        print(f"[SHARES] Total Drones (N): {n}")
        print(f"[SHARES] Threshold (K): {effective_k}")
        print(f"[SHARES] Recipients: {sorted(drone_ids)}")
        for d_id in sorted(drone_ids):
            share = self.drone_shares[d_id]
            print(f"[SHARES]   Drone {d_id}: Share index={share[0]}")
        print(f"[SHARES] {'='*50}\n")
    
    def register_joining_drone(self, drone_id: int) -> DroneCredentials:
        """
        Pre-register credentials for a drone that wants to join.
        In production, this would be done during drone manufacturing/provisioning.
        """
        if drone_id not in self.drone_credentials:
            self.drone_credentials[drone_id] = DroneCredentials(drone_id)
        return self.drone_credentials[drone_id]
    
    def _verify_certificate(self, certificate: Dict) -> bool:
        """Verify the drone's certificate is valid and signed by trusted CA."""
        if not certificate:
            return False
        
        # Check required fields
        required = ["drone_id", "public_key", "issuer", "issuer_signature", 
                    "valid_from", "valid_until"]
        if not all(field in certificate for field in required):
            return False
        
        # Check validity period
        now = time.time()
        if now < certificate["valid_from"] or now > certificate["valid_until"]:
            return False
        
        # Verify issuer signature (simulated)
        cert_data = f"{certificate['drone_id']}:{certificate['public_key']}"
        expected_sig = hashlib.sha256(f"CA_SIGNED:{cert_data}".encode()).hexdigest()
        
        return secrets.compare_digest(certificate["issuer_signature"], expected_sig)
    
    def _verify_request_signature(self, request: JoinRequest) -> bool:
        """Verify the signature on the join request."""
        if request.drone_id not in self.drone_credentials:
            return False
        
        creds = self.drone_credentials[request.drone_id]
        message = f"{request.drone_id}:{request.nonce}:{request.timestamp}"
        
        # In simulation, verify using stored credentials
        return DroneCredentials.verify_signature(
            creds.public_key, message, request.signature, creds.private_key
        )
    
    def _select_trusted_drones(self, current_drone_ids: List[int], 
                                leader_id: int) -> List[int]:
        """
        Leader selects K trusted drones to participate in secret reconstruction.
        Selection criteria: available, not blacklisted, preferring higher link quality.
        """
        available = [d_id for d_id in current_drone_ids 
                     if d_id in self.drone_shares and d_id not in self.blacklist]
        
        if len(available) < self.k_threshold:
            return available  # Return what we have
        
        # Prefer including the leader and randomly select remaining
        selected = []
        if leader_id in available:
            selected.append(leader_id)
            available.remove(leader_id)
        
        # Random selection for remaining slots
        remaining_needed = min(self.k_threshold, len(available) + len(selected)) - len(selected)
        selected.extend(random.sample(available, min(remaining_needed, len(available))))
        
        return selected
    
    def _reconstruct_master_secret(self, selected_drone_ids: List[int]) -> Optional[int]:
        """Collect shares from selected drones and reconstruct the master secret."""
        shares = []
        for d_id in selected_drone_ids:
            if d_id in self.drone_shares:
                shares.append(self.drone_shares[d_id])
        
        effective_k = min(self.k_threshold, len(shares))
        if len(shares) < effective_k:
            print(f"[AUTH] Insufficient shares: have {len(shares)}, need {effective_k}")
            return None
        
        try:
            x_coords = [s[0] for s in shares[:effective_k]]
            if self.sss_engine.x_coords != x_coords:
                self.sss_engine.precompute_weights(x_coords, ShamirSecretSharing.PRIME)
            return self.sss_engine.reconstruct_secret_fast(shares[:effective_k], self.sss_engine.weights, ShamirSecretSharing.PRIME)
        except Exception as e:
            print(f"[AUTH] Secret reconstruction failed: {e}")
            return None
    
    def _generate_challenge(self, secret: int, drone_id: int, nonce: str) -> str:
        """Generate authentication challenge: H(secret || Drone_ID || nonce)"""
        challenge_input = f"{secret}:{drone_id}:{nonce}"
        return hashlib.sha256(challenge_input.encode()).hexdigest()
    
    def validate_join_request(self, request: JoinRequest, 
                               current_time: float) -> Tuple[bool, str]:
        """
        Perform preliminary validation of a join request.
        
        Returns:
            (success, error_message)
        """
        # Check blacklist
        if request.drone_id in self.blacklist:
            return False, "Drone is blacklisted"
        
        # Check timestamp freshness (prevent replay attacks)
        if abs(current_time - request.timestamp) > self.TIMESTAMP_TOLERANCE:
            return False, "Request timestamp out of tolerance"
        
        # Verify certificate
        if not self._verify_certificate(request.certificate):
            return False, "Invalid certificate"
        
        # Verify request signature
        if not self._verify_request_signature(request):
            return False, "Invalid request signature"
        
        return True, "Preliminary validation passed"
    
    def initiate_authentication(self, request: JoinRequest, 
                                 current_drone_ids: List[int],
                                 leader_id: int,
                                 current_time: float) -> Tuple[bool, str, Optional[str]]:
        """
        Initiate the authentication process for a joining drone.
        
        Returns:
            (success, message, challenge) - challenge is None on failure
        """
        # Preliminary validation
        valid, error = self.validate_join_request(request, current_time)
        if not valid:
            print(f"[AUTH] Join request from drone {request.drone_id} rejected: {error}")
            return False, error, None
        
        # Select trusted drones for secret reconstruction
        selected = self._select_trusted_drones(current_drone_ids, leader_id)
        print(f"[AUTH] Selected drones for reconstruction: {selected}")
        
        if len(selected) < min(self.k_threshold, len(current_drone_ids)):
            return False, "Insufficient trusted drones for reconstruction", None
        
        # Reconstruct master secret
        secret = self._reconstruct_master_secret(selected)
        if secret is None:
            return False, "Failed to reconstruct master secret", None
        
        # Verify reconstructed secret matches (integrity check)
        if secret != self.master_secret:
            print("[AUTH] WARNING: Reconstructed secret mismatch - possible share corruption")
            return False, "Secret reconstruction integrity failure", None
        
        # Generate challenge
        challenge = self._generate_challenge(secret, request.drone_id, request.nonce)
        
        # Store pending authentication session
        self.pending_auth[request.drone_id] = {
            "challenge": challenge,
            "nonce": request.nonce,
            "start_time": current_time,
            "request": request
        }
        
        print(f"[AUTH] Challenge generated for drone {request.drone_id}: {challenge[:16]}...")
        return True, "Challenge issued", challenge
    
    def verify_challenge_response(self, response: ChallengeResponse,
                                    current_time: float) -> Tuple[bool, str]:
        """
        Verify the challenge response from the joining drone.
        
        Returns:
            (success, message)
        """
        drone_id = response.drone_id
        
        # Check if there's a pending auth session
        if drone_id not in self.pending_auth:
            print(f"[AUTH]   ✗ No pending authentication session found for drone {drone_id}")
            return False, "No pending authentication session"
        
        session = self.pending_auth[drone_id]
        
        # Check timeout
        elapsed = current_time - session["start_time"]
        if elapsed > self.AUTH_TIMEOUT:
            print(f"[AUTH]   ✗ Authentication timeout ({elapsed:.2f}s > {self.AUTH_TIMEOUT}s)")
            del self.pending_auth[drone_id]
            self._add_to_blacklist(drone_id, "Authentication timeout")
            return False, "Authentication timeout"
        
        # Verify challenge matches
        if response.challenge != session["challenge"]:
            print(f"[AUTH]   ✗ Challenge mismatch detected")
            print(f"[AUTH]   Expected: {session['challenge'][:32]}...")
            print(f"[AUTH]   Received: {response.challenge[:32]}...")
            del self.pending_auth[drone_id]
            self._add_to_blacklist(drone_id, "Challenge mismatch")
            return False, "Challenge mismatch"
        
        # Verify the signed response
        if drone_id not in self.drone_credentials:
            print(f"[AUTH]   ✗ No credentials found for drone {drone_id}")
            del self.pending_auth[drone_id]
            return False, "Unknown drone credentials"
        
        creds = self.drone_credentials[drone_id]
        
        # The drone signs the challenge to prove it has the private key
        expected_signature = creds.sign(response.challenge)
        
        if not secrets.compare_digest(response.response_signature, expected_signature):
            print(f"[AUTH]   ✗ Invalid challenge response signature")
            print(f"[AUTH]   The drone could not prove possession of private key")
            del self.pending_auth[drone_id]
            self._add_to_blacklist(drone_id, "Invalid challenge response signature")
            return False, "Invalid challenge response signature"
        
        # Authentication successful - clean up session
        del self.pending_auth[drone_id]
        return True, "Authentication successful"
    
    def _add_to_blacklist(self, drone_id: int, reason: str) -> None:
        """Add a drone to the blacklist."""
        self.blacklist.add(drone_id)
        print(f"\n{'!'*60}")
        print(f"[BLACKLIST] ╔════════════════════════════════════════════╗")
        print(f"[BLACKLIST] ║         DRONE BLACKLISTED                  ║")
        print(f"[BLACKLIST] ╠════════════════════════════════════════════╣")
        print(f"[BLACKLIST] ║  Drone ID: {drone_id:<32} ║")
        print(f"[BLACKLIST] ║  Reason: {reason:<34} ║")
        print(f"[BLACKLIST] ║  Status: Permanently blocked               ║")
        print(f"[BLACKLIST] ╚════════════════════════════════════════════╝")
        print(f"{'!'*60}\n")
    
    def is_blacklisted(self, drone_id: int) -> bool:
        """Check if a drone is blacklisted."""
        return drone_id in self.blacklist
    
    def on_drone_added(self, drone_ids: List[int]) -> None:
        """Called when drone membership changes - redistributes shares."""
        self.distribute_shares(drone_ids)
    
    def on_drone_removed(self, remaining_drone_ids: List[int]) -> None:
        """Called when a drone leaves - redistributes shares."""
        # Remove old share
        self.drone_shares = {k: v for k, v in self.drone_shares.items() 
                             if k in remaining_drone_ids}
        # Redistribute with remaining drones
        self.distribute_shares(remaining_drone_ids)


def authenticate_join_request(
    auth_module: ShamirAuthenticationModule,
    new_drone_id: int,
    current_drone_ids: List[int],
    leader_id: int,
    current_time: float
) -> Tuple[bool, str]:
    """
    High-level function to perform complete authentication for a joining drone.
    This is the GATING function that must pass before handle_join_request() is called.
    
    Returns:
        (authenticated, message)
    """
    print(f"\n{'='*60}")
    print(f"[AUTH] SHAMIR SECRET SHARING AUTHENTICATION")
    print(f"{'='*60}")
    print(f"[AUTH] Drone ID: {new_drone_id}")
    print(f"[AUTH] Timestamp: {current_time:.2f}s")
    print(f"[AUTH] Current Swarm Members: {sorted(current_drone_ids)}")
    print(f"[AUTH] Leader ID: {leader_id}")
    print(f"[AUTH] K-Threshold: {auth_module.k_threshold}")
    print(f"{'-'*60}")
    
    # Step 0: Pre-checks
    print(f"[AUTH] STEP 0: Pre-validation checks...")
    
    if new_drone_id in auth_module.blacklist:
        print(f"[AUTH]   ✗ BLACKLIST CHECK: Drone {new_drone_id} is BLACKLISTED")
        print(f"[AUTH]   Reason: Previously failed authentication")
        _print_auth_failure_summary(new_drone_id, "Drone is blacklisted")
        return False, "Drone is blacklisted"
    print(f"[AUTH]   ✓ Blacklist check passed")
    
    # Ensure the joining drone has pre-registered credentials
    print(f"[AUTH] STEP 1: Credential registration...")
    creds = auth_module.register_joining_drone(new_drone_id)
    print(f"[AUTH]   ✓ Credentials registered for drone {new_drone_id}")
    print(f"[AUTH]   Public Key: {creds.public_key[:16]}...")
    print(f"[AUTH]   Certificate Issuer: {creds.certificate['issuer']}")
    
    # Step 2: Create JOIN_REQUEST
    print(f"[AUTH] STEP 2: Creating JOIN_REQUEST...")
    nonce = secrets.token_hex(16)
    timestamp = current_time
    message = f"{new_drone_id}:{nonce}:{timestamp}"
    signature = creds.sign(message)
    
    request = JoinRequest(
        drone_id=new_drone_id,
        certificate=creds.certificate,
        nonce=nonce,
        signature=signature,
        timestamp=timestamp
    )
    print(f"[AUTH]   ✓ JOIN_REQUEST created")
    print(f"[AUTH]   Nonce: {nonce[:16]}...")
    print(f"[AUTH]   Request Signature: {signature[:16]}...")
    
    # Step 3: Preliminary validation
    print(f"[AUTH] STEP 3: Preliminary validation...")
    
    # Timestamp check
    time_diff = abs(current_time - request.timestamp)
    if time_diff > auth_module.TIMESTAMP_TOLERANCE:
        print(f"[AUTH]   ✗ TIMESTAMP CHECK FAILED")
        print(f"[AUTH]   Time difference: {time_diff:.2f}s (max allowed: {auth_module.TIMESTAMP_TOLERANCE}s)")
        _print_auth_failure_summary(new_drone_id, "Request timestamp out of tolerance")
        return False, "Request timestamp out of tolerance"
    print(f"[AUTH]   ✓ Timestamp valid (drift: {time_diff:.2f}s)")
    
    # Certificate validation
    if not auth_module._verify_certificate(request.certificate):
        print(f"[AUTH]   ✗ CERTIFICATE VALIDATION FAILED")
        print(f"[AUTH]   Possible reasons:")
        print(f"[AUTH]     - Certificate expired or not yet valid")
        print(f"[AUTH]     - Invalid CA signature")
        print(f"[AUTH]     - Missing required fields")
        _print_auth_failure_summary(new_drone_id, "Invalid certificate")
        return False, "Invalid certificate"
    print(f"[AUTH]   ✓ Certificate valid")
    print(f"[AUTH]     Valid from: {request.certificate['valid_from']}")
    print(f"[AUTH]     Valid until: {request.certificate['valid_until']}")
    
    # Request signature validation
    if not auth_module._verify_request_signature(request):
        print(f"[AUTH]   ✗ REQUEST SIGNATURE VALIDATION FAILED")
        print(f"[AUTH]   The signature does not match the drone's public key")
        _print_auth_failure_summary(new_drone_id, "Invalid request signature")
        return False, "Invalid request signature"
    print(f"[AUTH]   ✓ Request signature valid")
    
    # Step 4: Shamir Secret Reconstruction
    print(f"[AUTH] STEP 4: Shamir Secret Sharing reconstruction...")
    selected = auth_module._select_trusted_drones(current_drone_ids, leader_id)
    print(f"[AUTH]   Selected trusted drones: {selected}")
    print(f"[AUTH]   Number of shares to use: {len(selected)}")
    
    if len(selected) < min(auth_module.k_threshold, len(current_drone_ids)):
        print(f"[AUTH]   ✗ INSUFFICIENT TRUSTED DRONES")
        print(f"[AUTH]   Required: {auth_module.k_threshold}, Available: {len(selected)}")
        _print_auth_failure_summary(new_drone_id, "Insufficient trusted drones for reconstruction")
        return False, "Insufficient trusted drones for reconstruction"
    
    print(f"[AUTH]   Collecting shares from selected drones...")
    for d_id in selected:
        share = auth_module.drone_shares.get(d_id)
        if share:
            print(f"[AUTH]     Drone {d_id}: Share (x={share[0]}, y={str(share[1])[:20]}...)")
    
    secret = auth_module._reconstruct_master_secret(selected)
    if secret is None:
        print(f"[AUTH]   ✗ SECRET RECONSTRUCTION FAILED")
        print(f"[AUTH]   Could not reconstruct master secret from shares")
        _print_auth_failure_summary(new_drone_id, "Failed to reconstruct master secret")
        return False, "Failed to reconstruct master secret"
    
    if secret != auth_module.master_secret:
        print(f"[AUTH]   ✗ SECRET INTEGRITY CHECK FAILED")
        print(f"[AUTH]   Reconstructed secret does not match expected value")
        print(f"[AUTH]   Possible share corruption or tampering detected")
        _print_auth_failure_summary(new_drone_id, "Secret reconstruction integrity failure")
        return False, "Secret reconstruction integrity failure"
    
    print(f"[AUTH]   ✓ Master secret reconstructed successfully")
    print(f"[AUTH]   ✓ Secret integrity verified")
    
    # Step 5: Generate Challenge
    print(f"[AUTH] STEP 5: Challenge generation...")
    challenge = auth_module._generate_challenge(secret, new_drone_id, nonce)
    print(f"[AUTH]   Challenge = H(secret || {new_drone_id} || nonce)")
    print(f"[AUTH]   Challenge hash: {challenge[:32]}...")
    
    # Store pending auth session
    auth_module.pending_auth[new_drone_id] = {
        "challenge": challenge,
        "nonce": nonce,
        "start_time": current_time,
        "request": request
    }
    print(f"[AUTH]   ✓ Challenge issued to drone {new_drone_id}")
    
    # Step 6: Verify Challenge Response
    print(f"[AUTH] STEP 6: Challenge-response verification...")
    print(f"[AUTH]   Drone {new_drone_id} signing challenge with private key...")
    
    response_signature = creds.sign(challenge)
    response = ChallengeResponse(
        drone_id=new_drone_id,
        challenge=challenge,
        response_signature=response_signature
    )
    print(f"[AUTH]   Response signature: {response_signature[:32]}...")
    
    # Verify the response
    success, msg = auth_module.verify_challenge_response(response, current_time)
    
    if not success:
        print(f"[AUTH]   ✗ CHALLENGE RESPONSE VERIFICATION FAILED")
        print(f"[AUTH]   Reason: {msg}")
        _print_auth_failure_summary(new_drone_id, msg)
        return False, msg
    
    print(f"[AUTH]   ✓ Challenge response verified successfully")
    
    # Success!
    _print_auth_success_summary(new_drone_id, current_drone_ids, leader_id, auth_module.k_threshold)
    return True, "Authenticated"


def _print_auth_failure_summary(drone_id: int, reason: str):
    """Print a formatted authentication failure summary."""
    print(f"\n{'-'*60}")
    print(f"[AUTH] ╔══════════════════════════════════════════════════════╗")
    print(f"[AUTH] ║          AUTHENTICATION FAILED                       ║")
    print(f"[AUTH] ╠══════════════════════════════════════════════════════╣")
    print(f"[AUTH] ║  Drone ID: {drone_id:<43} ║")
    print(f"[AUTH] ║  Status: REJECTED                                    ║")
    print(f"[AUTH] ║  Reason: {reason:<44} ║")
    print(f"[AUTH] ║  Action: Drone NOT allowed to join swarm             ║")
    print(f"[AUTH] ║  Note: Drone may be added to blacklist               ║")
    print(f"[AUTH] ╚══════════════════════════════════════════════════════╝")
    print(f"{'='*60}\n")


def _print_auth_success_summary(drone_id: int, swarm_members: List[int], 
                                 leader_id: int, k_threshold: int):
    """Print a formatted authentication success summary."""
    print(f"\n{'-'*60}")
    print(f"[AUTH] ╔══════════════════════════════════════════════════════╗")
    print(f"[AUTH] ║          AUTHENTICATION SUCCESSFUL                   ║")
    print(f"[AUTH] ╠══════════════════════════════════════════════════════╣")
    print(f"[AUTH] ║  Drone ID: {drone_id:<43} ║")
    print(f"[AUTH] ║  Status: APPROVED                                    ║")
    print(f"[AUTH] ║  Authentication Method: Shamir Secret Sharing        ║")
    print(f"[AUTH] ║  K-Threshold: {k_threshold:<40} ║")
    print(f"[AUTH] ║  Authenticating Leader: Drone {leader_id:<23} ║")
    print(f"[AUTH] ║  Current Swarm Size: {len(swarm_members):<33} ║")
    print(f"[AUTH] ║  Action: Drone CLEARED to join swarm                 ║")
    print(f"[AUTH] ╚══════════════════════════════════════════════════════╝")
    print(f"{'='*60}\n")


class FakeDroneSimulator:
    """
    Simulates malicious/fake drones with various types of authentication failures.
    Used for testing the robustness of the Shamir authentication system.
    """
    
    def __init__(self):
        self.fake_attempt_counter = 1000  # Start fake drone IDs from 1000
    
    def create_fake_drone_with_invalid_signature(self, auth_module: ShamirAuthenticationModule, 
                                                  current_time: float) -> Tuple[int, JoinRequest]:
        """Create a fake drone with an invalid signature on the JOIN_REQUEST."""
        fake_id = self.fake_attempt_counter
        self.fake_attempt_counter += 1
        
        # Create legitimate credentials first
        fake_creds = DroneCredentials(fake_id)
        
        # Create request with WRONG signature (using wrong message)
        nonce = secrets.token_hex(16)
        timestamp = current_time
        correct_message = f"{fake_id}:{nonce}:{timestamp}"
        wrong_message = f"{fake_id}:WRONG_NONCE:{timestamp}"  # Deliberately wrong
        
        # Sign the wrong message (this will cause signature verification to fail)
        invalid_signature = fake_creds.sign(wrong_message)
        
        request = JoinRequest(
            drone_id=fake_id,
            certificate=fake_creds.certificate,
            nonce=nonce,
            signature=invalid_signature,  # Invalid signature!
            timestamp=timestamp
        )
        
        # Store fake credentials so verification can access them
        auth_module.drone_credentials[fake_id] = fake_creds
        
        return fake_id, request
    
    def create_fake_drone_with_expired_certificate(self, auth_module: ShamirAuthenticationModule,
                                                   current_time: float) -> Tuple[int, JoinRequest]:
        """Create a fake drone with an expired certificate."""
        fake_id = self.fake_attempt_counter
        self.fake_attempt_counter += 1
        
        fake_creds = DroneCredentials(fake_id)
        
        # Modify certificate to be expired
        fake_creds.certificate['valid_from'] = current_time - 1000  # Long ago
        fake_creds.certificate['valid_until'] = current_time - 500   # Expired
        
        nonce = secrets.token_hex(16)
        timestamp = current_time
        message = f"{fake_id}:{nonce}:{timestamp}"
        signature = fake_creds.sign(message)
        
        request = JoinRequest(
            drone_id=fake_id,
            certificate=fake_creds.certificate,  # Expired!
            nonce=nonce,
            signature=signature,
            timestamp=timestamp
        )
        
        auth_module.drone_credentials[fake_id] = fake_creds
        return fake_id, request
    
    def create_fake_drone_with_tampered_certificate(self, auth_module: ShamirAuthenticationModule,
                                                    current_time: float) -> Tuple[int, JoinRequest]:
        """Create a fake drone with a tampered certificate signature."""
        fake_id = self.fake_attempt_counter
        self.fake_attempt_counter += 1
        
        fake_creds = DroneCredentials(fake_id)
        
        # Tamper with the certificate signature
        fake_creds.certificate['issuer_signature'] = "TAMPERED_SIGNATURE_INVALID"
        
        nonce = secrets.token_hex(16)
        timestamp = current_time
        message = f"{fake_id}:{nonce}:{timestamp}"
        signature = fake_creds.sign(message)
        
        request = JoinRequest(
            drone_id=fake_id,
            certificate=fake_creds.certificate,  # Tampered!
            nonce=nonce,
            signature=signature,
            timestamp=timestamp
        )
        
        auth_module.drone_credentials[fake_id] = fake_creds
        return fake_id, request

    def create_fake_drone_with_old_timestamp(self, auth_module: ShamirAuthenticationModule,
                                             current_time: float) -> Tuple[int, JoinRequest]:
        """Create a fake drone with an old timestamp (replay attack)."""
        fake_id = self.fake_attempt_counter
        self.fake_attempt_counter += 1
        
        fake_creds = DroneCredentials(fake_id)
        
        nonce = secrets.token_hex(16)
        old_timestamp = current_time - 120.0  # 2 minutes old (exceeds tolerance)
        message = f"{fake_id}:{nonce}:{old_timestamp}"
        signature = fake_creds.sign(message)
        
        request = JoinRequest(
            drone_id=fake_id,
            certificate=fake_creds.certificate,
            nonce=nonce,
            signature=signature,
            timestamp=old_timestamp  # Too old!
        )
        
        auth_module.drone_credentials[fake_id] = fake_creds
        return fake_id, request

def test_fake_drone_authentication(leader: 'ClusterLeader', current_time: float, 
                                   fake_type: str = "invalid_signature") -> bool:
    """
    Test the authentication system with various types of fake/malicious drones.
    
    Args:
        leader: ClusterLeader instance
        current_time: Current simulation time
        fake_type: Type of fake drone to create
            - "invalid_signature": Wrong signature on JOIN_REQUEST
            - "expired_cert": Expired certificate
            - "tampered_cert": Tampered certificate signature  
            - "old_timestamp": Replay attack with old timestamp
    
    Returns:
        True if fake drone was correctly rejected, False if it was incorrectly accepted
    """
    print(f"\n{'🛡️'*15} SECURITY TEST {'🛡️'*15}")
    print(f"[FAKE DRONE TEST] {'🧪'*50}")
    print(f"[FAKE DRONE TEST] TESTING MALICIOUS DRONE REJECTION")
    print(f"[FAKE DRONE TEST] Attack Type: {fake_type.upper()}")
    print(f"[FAKE DRONE TEST] {'🧪'*50}")
    
    fake_simulator = FakeDroneSimulator()
    
    # Create fake drone based on type
    if fake_type == "invalid_signature":
        fake_id, fake_request = fake_simulator.create_fake_drone_with_invalid_signature(
            leader.auth_module, current_time)
        print(f"[FAKE DRONE TEST] 🎭 Created fake drone {fake_id} with INVALID SIGNATURE")
        print(f"[FAKE DRONE TEST] 📝 Attack: Signing wrong message to bypass auth")
        
    elif fake_type == "expired_cert":
        fake_id, fake_request = fake_simulator.create_fake_drone_with_expired_certificate(
            leader.auth_module, current_time)
        print(f"[FAKE DRONE TEST] 📅 Created fake drone {fake_id} with EXPIRED CERTIFICATE")
        print(f"[FAKE DRONE TEST] 📝 Attack: Using outdated credentials")
        
    elif fake_type == "tampered_cert":
        fake_id, fake_request = fake_simulator.create_fake_drone_with_tampered_certificate(
            leader.auth_module, current_time)
        print(f"[FAKE DRONE TEST] 🔒 Created fake drone {fake_id} with TAMPERED CERTIFICATE")
        print(f"[FAKE DRONE TEST] 📝 Attack: Forged CA signature")
        
    elif fake_type == "old_timestamp":
        fake_id, fake_request = fake_simulator.create_fake_drone_with_old_timestamp(
            leader.auth_module, current_time)
        print(f"[FAKE DRONE TEST] ⏰ Created fake drone {fake_id} with OLD TIMESTAMP")
        print(f"[FAKE DRONE TEST] 📝 Attack: Replay attack with stale request")
        
    else:
        print(f"[FAKE DRONE TEST] ❓ Unknown fake type: {fake_type}")
        return False
    
    print(f"[FAKE DRONE TEST] 🔍 Testing if authentication correctly rejects malicious drone...")
    
    # Directly test the authentication without going through secure_join_request
    current_drone_ids = list(leader.drones.keys())
    
    if leader.current_leader_id is None or leader.current_leader_id not in leader.drones:
        print(f"[FAKE DRONE TEST] ❌ Cannot test - no leader available")
        print(f"{'🛡️'*45}\n")
        return False
    
    # Test preliminary validation
    valid, error = leader.auth_module.validate_join_request(fake_request, current_time)
    
    if not valid:
        print(f"[FAKE DRONE TEST] {'✅'*3} SUCCESS! {'✅'*3}")
        print(f"[FAKE DRONE TEST] 🛡️ SECURITY SYSTEM WORKING PROPERLY")
        print(f"[FAKE DRONE TEST] 🚫 Fake drone correctly REJECTED")
        print(f"[FAKE DRONE TEST] 📋 Rejection reason: {error}")
        print(f"[FAKE DRONE TEST] 🎯 Authentication prevented malicious access!")
        print(f"{'🛡️'*45}\n")
        return True
    else:
        print(f"[FAKE DRONE TEST] {'🚨'*3} CRITICAL FAILURE! {'🚨'*3}")
        print(f"[FAKE DRONE TEST] ⚠️ SECURITY VULNERABILITY DETECTED")
        print(f"[FAKE DRONE TEST] 💥 Fake drone incorrectly PASSED validation")
        print(f"[FAKE DRONE TEST] 🔓 This indicates a serious security flaw!")
        print(f"{'🛡️'*45}\n")
        return False


def test_real_drone_authentication(leader: 'ClusterLeader', current_time: float) -> bool:
    """
    Test the authentication system with a legitimate drone that should be accepted.
    
    Returns:
        True if real drone was correctly accepted, False if it was incorrectly rejected
    """
    print(f"\n{'🎯'*15} LEGITIMATE TEST {'🎯'*15}")
    print(f"[REAL DRONE TEST] {'✅'*50}")
    print(f"[REAL DRONE TEST] TESTING LEGITIMATE DRONE ACCEPTANCE")
    print(f"[REAL DRONE TEST] {'✅'*50}")
    
    # Check pre-conditions
    if len(leader.drones) >= 6:
        print(f"[REAL DRONE TEST] ⚠️ Cannot test - swarm at max capacity ({len(leader.drones)}/6)")
        print(f"[REAL DRONE TEST] 📝 Try removing a drone first (press '6')")
        print(f"{'🎯'*45}\n")
        return False
    
    if leader.current_leader_id is None or leader.current_leader_id not in leader.drones:
        print(f"[REAL DRONE TEST] ❌ Cannot test - no leader available")
        print(f"[REAL DRONE TEST] 📝 Wait for leader election to complete")
        print(f"{'🎯'*45}\n")
        return False
    
    # Get next drone ID that should join
    next_id = (max(leader.drones.keys()) + 1) if leader.drones else 1
    
    print(f"[REAL DRONE TEST] 🤖 Testing legitimate drone {next_id} authentication...")
    print(f"[REAL DRONE TEST] 🔐 Using proper credentials and valid certificate")
    print(f"[REAL DRONE TEST] 📡 Current swarm size: {len(leader.drones)}")
    print(f"[REAL DRONE TEST] 👑 Leader: Drone {leader.current_leader_id}")
    
    # Attempt secure join
    success = leader.secure_join_request(next_id, current_time)
    
    if success:
        print(f"[REAL DRONE TEST] {'🎉'*3} SUCCESS! {'🎉'*3}")
        print(f"[REAL DRONE TEST] ✅ AUTHENTICATION SYSTEM WORKING PROPERLY")
        print(f"[REAL DRONE TEST] 🤖 Real drone correctly ACCEPTED")
        print(f"[REAL DRONE TEST] 📊 Drone {next_id} authenticated and joined swarm!")
        print(f"[REAL DRONE TEST] 📈 New swarm size: {len(leader.drones)}")
        print(f"[REAL DRONE TEST] 🔗 Shares redistributed to all members")
        print(f"{'🎯'*45}\n")
        return True
    else:
        print(f"[REAL DRONE TEST] {'🐛'*3} SYSTEM BUG! {'🐛'*3}")
        print(f"[REAL DRONE TEST] ❌ AUTHENTICATION MALFUNCTION DETECTED")
        print(f"[REAL DRONE TEST] 💥 Real drone incorrectly REJECTED")
        print(f"[REAL DRONE TEST] 🔧 This indicates a system bug or misconfiguration!")
        print(f"{'🎯'*45}\n")
        return False


# =========================
# Global config / placeholders
# =========================

# Path to the drone URDF model file used for visuals in PyBullet.
# If this fails, the code falls back to drawing a simple sphere for each drone.
# Set to None to skip URDF loading and use simple sphere representation
DRONE_URDF_PATH = None


# =========================
# Helper
# =========================

def angle_wrap(angle: float) -> float:
    """Wrap angle to [-pi, pi).

    Explanation:
    - Keeps angles normalized so comparisons and differences are stable.
    - Useful when computing shortest angular differences (e.g., theta_target - theta).
    """
    return (angle + math.pi) % (2 * math.pi) - math.pi


# =========================
# Drone in PyBullet
# =========================

class DronePB:
    """
    DronePB: a single drone simulated in PyBullet.

    Modes:
    - ORBIT: drone orbits around the building at r_target, theta increases (spin).
    - RECALIB: drone moves smoothly to a new slot (r_target, theta_target) without spinning.
    - TO_BASE: drone flies back to the base station (used on leave).
    - FROM_BASE: drone flies from base to its assigned orbit slot (used on join).
    - AT_BASE: drone is parked at base (ready to be removed or re-used).

    Comments inside methods explain the small details of motion and state updates.
    """

    def __init__(
        self,
        drone_id: int,
        client_id: int,
        r: float,
        theta: float,
        altitude: float,
        building_center: Tuple[float, float],
        base_world_pos: Tuple[float, float, float],
        start_at_base: bool = False,
    ):
        # Unique numeric id for this drone (1,2,...). Used for sorting, elections, logs.
        self.id = drone_id
        # PyBullet client id (which physics instance we belong to).
        self.client_id = client_id
        # Center of the building (x,y) — drones orbit around this point.
        self.cx, self.cy = building_center

        # Base station world coordinates (where drones go to leave / spawn from).
        self.base_x, self.base_y, self.base_z = base_world_pos

        # Initialize position/state depending on whether the drone starts at base or on orbit.
        if start_at_base:
            # If starting at base, place at base coordinates and compute polar coords
            self.x = self.base_x
            self.y = self.base_y
            self.z = altitude
            dx = self.x - self.cx
            dy = self.y - self.cy
            self.r = math.sqrt(dx * dx + dy * dy)
            self.theta = math.atan2(dy, dx)
            self.mode = "AT_BASE"  # parked at base until commanded
        else:
            # If starting on orbit, set polar coordinates directly
            self.r = r
            self.theta = theta
            self.z = altitude
            self.x, self.y = self._polar_to_cartesian(self.r, self.theta)
            self.mode = "ORBIT"  # ready to orbit

        # fixed flight altitude for this drone
        self.altitude = altitude

        # Targets for ring motion (where this drone wants to be on the orbit)
        self.r_target = self.r
        self.theta_target = self.theta

        # Reserved future targets used when a JOIN is pending (so current drones
        # know the reserved slot for the joining drone)
        self.future_r_target = self.r
        self.future_theta_target = self.theta
        # When true, the drone is waiting for the leader's GO to start recalibration
        self.waiting_for_recalib = False  # after JOIN_ACCEPTED

        # Simple proportional controller gains used by the built-in formation controller
        self.k_r = 0.8
        self.k_theta = 1.2
        # base angular velocity used while in ORBIT mode (constant spin)
        self.omega_base = 0.3  # base spin in ORBIT

        # Speed limits used during RECALIB mode to keep movement smooth and graceful
        self.max_recalib_radial_speed = 4.0     # m/s max radial speed
        self.max_recalib_angular_speed = 0.6    # rad/s max angular speed

        # Battery sim (value 0..100). Drill down used for leader election weights.
        self.battery = 100.0
        # Each drone has a slightly different drain rate to create variation.
        self.battery_drain_rate = random.uniform(0.3, 0.7)

        # Speed for flying to/from base (TO_BASE / FROM_BASE)
        self.transit_speed = 8.0  # m/s

        # Metrics used for leader election (updated by ClusterLeader)
        self.link_quality = 1.0           # [0,1], how well this drone connects to neighbors
        self.leader_confidence = 0.0      # [0,1], self confidence for election
        self.leader_score = 0.0           # scalar combined score used in election

        # Visual / physical body creation: try to load URDF; otherwise fall back to sphere.
        start_pos = [self.x, self.y, self.z]
        start_orn = p.getQuaternionFromEuler([0, 0, 0])

        global DRONE_URDF_PATH
        if DRONE_URDF_PATH:
            try:
                # load a detailed drone model for nicer visuals
                self.body_id = p.loadURDF(
                    DRONE_URDF_PATH,
                    start_pos,
                    start_orn,
                    globalScaling=8,
                    physicsClientId=self.client_id,
                )
            except Exception as e:
                # If URDF load fails, we gracefully degrade to a simple sphere.
                print(f"[WARN] Failed to load URDF '{DRONE_URDF_PATH}': {e}")
                print("[WARN] Falling back to simple sphere drone.")
                radius = 0.3
                col_shape = p.createCollisionShape(
                    p.GEOM_SPHERE, radius=radius, physicsClientId=self.client_id
                )
                vis_shape = p.createVisualShape(
                    p.GEOM_SPHERE,
                    radius=radius,
                    rgbaColor=[0.1, 0.8, 0.1, 1.0],
                    physicsClientId=self.client_id,
                )
                self.body_id = p.createMultiBody(
                    baseMass=1.0,
                    baseCollisionShapeIndex=col_shape,
                    baseVisualShapeIndex=vis_shape,
                    basePosition=start_pos,
                    baseOrientation=start_orn,
                    physicsClientId=self.client_id,
                )
        else:
            # If no URDF path provided, create a sphere body to represent the drone.
            radius = 0.3
            col_shape = p.createCollisionShape(
                p.GEOM_SPHERE, radius=radius, physicsClientId=self.client_id
            )
            vis_shape = p.createVisualShape(
                p.GEOM_SPHERE,
                radius=radius,
                rgbaColor=[0.1, 0.8, 0.1, 1.0],
                physicsClientId=self.client_id,
            )
            self.body_id = p.createMultiBody(
                baseMass=1.0,
                baseCollisionShapeIndex=col_shape,
                baseVisualShapeIndex=vis_shape,
                basePosition=start_pos,
                baseOrientation=start_orn,
                physicsClientId=self.client_id,
            )

    # ---- Utilities ----

    def _polar_to_cartesian(self, r: float, theta: float) -> Tuple[float, float]:
        """Convert polar coordinates (r,theta) around building center to x,y world coords."""
        x = self.cx + r * math.cos(theta)
        y = self.cy + r * math.sin(theta)
        return x, y

    def _update_body(self):
        """Apply current (x,y,z) to the PyBullet object so visuals move."""
        pos = [self.x, self.y, self.z]
        orn = p.getQuaternionFromEuler([0, 0, 0])
        p.resetBasePositionAndOrientation(
            self.body_id, pos, orn, physicsClientId=self.client_id
        )

    def set_color(self, rgba):
        """Change the visual color of this drone's body (used to mark leader/follower)."""
        p.changeVisualShape(
            self.body_id, -1, rgbaColor=rgba, physicsClientId=self.client_id
        )

    def remove_from_world(self):
        """Remove the PyBullet body for this drone (called when drone leaves)."""
        p.removeBody(self.body_id, physicsClientId=self.client_id)

    # ---- Commands ----

    def go_to_base(self):
        """Command: start leaving the orbit and fly to base (TO_BASE)."""
        if self.mode in ("ORBIT", "RECALIB"):
            self.mode = "TO_BASE"

    def go_from_base_to_orbit(self, r_target: float, theta_target: float):
        """Command: begin flight from base to assigned orbit slot (FROM_BASE)."""
        self.r_target = r_target
        self.theta_target = theta_target
        self.mode = "FROM_BASE"

    # ---- Step (GRACEFUL ORBIT + RECALIB) ----

    def step(self, dt: float):
        """Per-frame update for the drone: battery, motion depending on mode, and visuals."""

        # Battery drain simulation: drains slowly each timestep
        if self.battery > 0.0:
            self.battery -= self.battery_drain_rate * dt
            if self.battery < 0.0:
                self.battery = 0.0

        # ---- ORBIT: constant spin + small radial correction ----
        if self.mode == "ORBIT":
            # radial error and proportional radial velocity to track r_target
            e_r = self.r_target - self.r
            v_r = self.k_r * e_r
            self.r += v_r * dt

            # constant angular speed (base spin)
            self.theta += self.omega_base * dt
            self.theta = angle_wrap(self.theta)

            # update cartesian coordinates and visuals
            self.x, self.y = self._polar_to_cartesian(self.r, self.theta)
            self.z = self.altitude
            self._update_body()

        # ---- RECALIB: smooth move to new (r_target, theta_target) without spinning ----
        elif self.mode == "RECALIB":
            # radial and angular errors (angular wrapped to [-pi,pi])
            e_r = self.r_target - self.r
            e_theta = angle_wrap(self.theta_target - self.theta)

            # raw control values (proportional)
            v_r = self.k_r * e_r
            omega = self.k_theta * e_theta

            # clamp radial and angular velocities to keep motion graceful and avoid overshoot
            if v_r > self.max_recalib_radial_speed:
                v_r = self.max_recalib_radial_speed
            elif v_r < -self.max_recalib_radial_speed:
                v_r = -self.max_recalib_radial_speed

            if omega > self.max_recalib_angular_speed:
                omega = self.max_recalib_angular_speed
            elif omega < -self.max_recalib_angular_speed:
                omega = -self.max_recalib_angular_speed

            # integrate position
            self.r += v_r * dt
            self.theta += omega * dt
            self.theta = angle_wrap(self.theta)

            # update cartesian and visuals
            self.x, self.y = self._polar_to_cartesian(self.r, self.theta)
            self.z = self.altitude
            self._update_body()

        # ---- TO_BASE / FROM_BASE: straight-line transit with constant speed ----
        elif self.mode in ("TO_BASE", "FROM_BASE"):
            if self.mode == "TO_BASE":
                # target is base coordinates
                tx, ty, tz = self.base_x, self.base_y, self.base_z
            else:  # FROM_BASE
                # target is the assigned orbit slot
                tx, ty = self._polar_to_cartesian(self.r_target, self.theta_target)
                tz = self.altitude

            # vector to target
            dx = tx - self.x
            dy = ty - self.y
            dz = tz - self.z
            dist = math.sqrt(dx * dx + dy * dy + dz * dz)

            # If very close to target, snap to it and change mode accordingly
            if dist < 0.3:
                self.x, self.y, self.z = tx, ty, tz
                if self.mode == "TO_BASE":
                    self.mode = "AT_BASE"  # parked
                else:
                    self.mode = "ORBIT"   # arrived and start orbiting
                    self.r = self.r_target
                    self.theta = self.theta_target
                self._update_body()
            else:
                # move along the direction toward the target with transit_speed
                ux, uy, uz = dx / dist, dy / dist, dz / dist
                step_dist = self.transit_speed * dt
                if step_dist > dist:
                    step_dist = dist
                self.x += ux * step_dist
                self.y += uy * step_dist
                self.z += uz * step_dist
                # update polar coordinates (used by orbit controller)
                rel_x = self.x - self.cx
                rel_y = self.y - self.cy
                self.r = math.sqrt(rel_x * rel_x + rel_y * rel_y)
                self.theta = math.atan2(rel_y, rel_x)
                self._update_body()

        # ---- AT_BASE: remain at base and update visuals ----
        elif self.mode == "AT_BASE":
            self.x, self.y, self.z = self.base_x, self.base_y, self.base_z
            self._update_body()


# =========================
# Logical Leader / Cluster Manager
# =========================

class ClusterLeader:
    """
    ClusterLeader: logical manager for the drone cluster.
    Responsibilities:
    - compute and broadcast formation slots (r,theta)
    - handle JOIN protocol (reserve slots, spawn new drone)
    - handle LEAVE protocol (remove drones)
    - perform leader election using a ring-based token/message algorithm
    - track periodic re-election using orbit rounds
    - update link quality and leader scores used in election
    - SECURE JOIN via Shamir Secret Sharing authentication
    """

    def __init__(
        self,
        client_id: int,
        drones: Dict[int, DronePB],
        building_radius: float = 10.0,
        margin: float = 15.0,
        d_safe: float = 8.0,
        theta0: float = 0.0,
        building_center: Tuple[float, float] = (0.0, 0.0),
        drone_altitude: float = 15.0,
        election_interval: float = 25.0,
        low_battery_threshold: float = 30.0,
        join_timeout: float = 6.0,
        comm_range: float = 60.0,
        shamir_k_threshold: int = 3,
    ):
        # PyBullet client id to update visuals if needed
        self.client_id = client_id
        # dictionary mapping drone_id -> DronePB (active drones in cluster)
        self.drones: Dict[int, DronePB] = drones

        # formation parameters
        self.building_radius = building_radius
        self.margin = margin
        self.d_safe = d_safe
        self.theta0 = theta0
        self.building_center = building_center
        self.drone_altitude = drone_altitude

        # current ring radius (computed from formation parameters)
        self.r_current = None
        # versioning counter to label formation updates (useful for logs)
        self.version = 0

        # Leader election state
        self.current_leader_id = None
        self.last_failed_leader_id = None
        self.last_election_time = 0.0
        self.election_interval = election_interval
        self.low_battery_threshold = low_battery_threshold

        # Recalibration state (True while drones are moving to new slots)
        self.recalib_in_progress = False

        # Robust JOIN state: track a single pending join request
        self.pending_join_id = None
        self.pending_join_time = None
        self.join_timeout = join_timeout
        # future_slots: dictionary mapping drone_id -> (r, theta) reserved for next formation
        self.future_slots = {}  # id -> (r, theta)

        # communication model: max distance where two drones can talk
        self.comm_range = comm_range

        # === Shamir Secret Sharing Authentication Module ===
        self.auth_module = ShamirAuthenticationModule(k_threshold=shamir_k_threshold)
        # Initialize shares for existing drones
        if drones:
            self.auth_module.distribute_shares(list(drones.keys()))

        # auto election suppression (used during scripted scenario buffers)
        self.auto_election_suppressed_until = None

        # Visual leader marker handles (created lazily)
        self.leader_sphere_id = None
        self.leader_debug_id = None

        # orbit tracking for periodic re-election after a number of rounds
        self.periodic_rounds_threshold = 3
        self.rounds_since_last_election = 0
        self.orbit_unwrapped = 0.0
        self.prev_theta_ref = None
        # choose a reference drone id (minimum id by default) to track angular progress
        self.reference_id = min(drones.keys()) if drones else None

    # -------- SECURE JOIN with Shamir Authentication --------

    def secure_join_request(self, new_drone_id: int, t: float) -> bool:
        """
        SECURE JOIN GATE: Authenticate drone before allowing join.
        
        This method MUST be called instead of handle_join_request() directly.
        Authentication occurs BEFORE slot reservation and drone spawning.
        
        Flow:
        1. Check if drone is blacklisted
        2. Perform Shamir-based authentication
        3. On success: proceed to handle_join_request()
        4. On failure: reject and blacklist drone
        
        Returns:
            True if authentication passed and join was accepted, False otherwise
        """
        print(f"\n{'#'*60}")
        print(f"[SECURE JOIN] DRONE JOIN REQUEST RECEIVED")
        print(f"{'#'*60}")
        print(f"[SECURE JOIN] Requesting Drone ID: {new_drone_id}")
        print(f"[SECURE JOIN] Request Time: {t:.2f}s")
        print(f"[SECURE JOIN] Current Swarm Size: {len(self.drones)}")
        print(f"[SECURE JOIN] Max Swarm Capacity: 6")
        print(f"{'#'*60}")
        
        # Pre-check: is drone blacklisted?
        if self.auth_module.is_blacklisted(new_drone_id):
            print(f"\n[SECURE JOIN] PRE-CHECK FAILED: Drone {new_drone_id} is BLACKLISTED")
            print(f"[SECURE JOIN] ╔══════════════════════════════════════════════╗")
            print(f"[SECURE JOIN] ║  JOIN REQUEST: DENIED                        ║")
            print(f"[SECURE JOIN] ║  Reason: Drone is on blacklist               ║")
            print(f"[SECURE JOIN] ║  Action: Request ignored                     ║")
            print(f"[SECURE JOIN] ╚══════════════════════════════════════════════╝")
            print(f"{'#'*60}\n")
            return False
        
        # Pre-check: cluster capacity
        if len(self.drones) >= 6:
            print(f"\n[SECURE JOIN] PRE-CHECK FAILED: Cluster at maximum capacity")
            print(f"[SECURE JOIN] ╔══════════════════════════════════════════════╗")
            print(f"[SECURE JOIN] ║  JOIN REQUEST: DENIED                        ║")
            print(f"[SECURE JOIN] ║  Reason: Swarm at max capacity (6 drones)    ║")
            print(f"[SECURE JOIN] ║  Action: Request rejected                    ║")
            print(f"[SECURE JOIN] ╚══════════════════════════════════════════════╝")
            print(f"{'#'*60}\n")
            return False
        
        # Pre-check: leader must exist for authentication
        if self.current_leader_id is None or self.current_leader_id not in self.drones:
            print(f"\n[SECURE JOIN] PRE-CHECK FAILED: No leader available")
            print(f"[SECURE JOIN] ╔══════════════════════════════════════════════╗")
            print(f"[SECURE JOIN] ║  JOIN REQUEST: DENIED                        ║")
            print(f"[SECURE JOIN] ║  Reason: No leader to coordinate auth        ║")
            print(f"[SECURE JOIN] ║  Action: Request deferred                    ║")
            print(f"[SECURE JOIN] ╚══════════════════════════════════════════════╝")
            print(f"{'#'*60}\n")
            return False
        
        print(f"[SECURE JOIN] ✓ All pre-checks passed")
        print(f"[SECURE JOIN] Initiating Shamir Secret Sharing authentication...")
        
        # Perform Shamir Secret Sharing based authentication
        current_drone_ids = list(self.drones.keys())
        authenticated, message = authenticate_join_request(
            auth_module=self.auth_module,
            new_drone_id=new_drone_id,
            current_drone_ids=current_drone_ids,
            leader_id=self.current_leader_id,
            current_time=t
        )
        
        if not authenticated:
            print(f"[SECURE JOIN] ╔══════════════════════════════════════════════╗")
            print(f"[SECURE JOIN] ║  JOIN REQUEST: DENIED                        ║")
            print(f"[SECURE JOIN] ║  Reason: Authentication failed               ║")
            print(f"[SECURE JOIN] ║  Details: {message:<33} ║")
            print(f"[SECURE JOIN] ║  Action: Drone NOT spawned                   ║")
            print(f"[SECURE JOIN] ╚══════════════════════════════════════════════╝")
            print(f"{'#'*60}\n")
            return False
        
        # Authentication passed - proceed with join
        print(f"[SECURE JOIN] ╔══════════════════════════════════════════════╗")
        print(f"[SECURE JOIN] ║  JOIN REQUEST: APPROVED                      ║")
        print(f"[SECURE JOIN] ║  Authentication: PASSED                      ║")
        print(f"[SECURE JOIN] ║  Action: Proceeding to slot reservation      ║")
        print(f"[SECURE JOIN] ╚══════════════════════════════════════════════╝")
        
        # Call the original join handler
        self.handle_join_request(new_drone_id, t)
        
        print(f"[SECURE JOIN] ✓ Drone {new_drone_id} successfully processed")
        print(f"{'#'*60}\n")
        return True

    # -------- Formation for CURRENT drones --------

    def recompute_formation_current(self):
        """
        Compute a new evenly spaced formation for the CURRENT active drones.
        Sets r_target and theta_target for each drone and puts them into RECALIB mode.
        """
        member_ids: List[int] = sorted(self.drones.keys())
        N = len(member_ids)
        if N == 0:
            self.r_current = None
            return

        # base radius (building + margin) and safety spacing depending on N
        r_base = self.building_radius + self.margin
        if N > 1:
            # r_safe ensures pairwise distance >= d_safe
            r_safe = self.d_safe / (2 * math.sin(math.pi / N))
        else:
            r_safe = r_base
        r = max(r_base, r_safe)
        self.r_current = r

        delta_theta = 2 * math.pi / N

        # assign each sorted drone an evenly spaced slot and set RECALIB mode
        for i, d_id in enumerate(member_ids):
            theta_star = self.theta0 + i * delta_theta
            d = self.drones[d_id]
            d.r_target = r
            d.theta_target = angle_wrap(theta_star)
            d.mode = "RECALIB"  # force movement to new slot

        # Log the broadcasted targets so user / evaluator can see them
        print("[Leader] Broadcasted new coordinates to CURRENT drones (formation recompute):")
        for d_id in member_ids:
            d = self.drones[d_id]
            print(f"    Drone {d_id}: r_target={d.r_target:.2f}, theta_target={d.theta_target:.2f}")

        # mark recalibration in progress and increment formation version
        self.recalib_in_progress = True
        self.version += 1
        print(f"[Leader] Formation v{self.version}: N={N}, r={r:.2f} (RECALIB CURRENT)")

    def _finish_recalibration_if_done(self):
        """
        Check whether all drones have reached their RECALIB targets.
        If so, switch them back to ORBIT and clear the recalibration flag.
        """
        if not self.recalib_in_progress:
            return

        # If any drone is still flying FROM_BASE, we keep the cluster frozen.
        for d in self.drones.values():
            if d.mode == "FROM_BASE":
                return

        # Check distance to respective targets for all RECALIB drones
        all_done = True
        for d in self.drones.values():
            if d.mode != "RECALIB":
                continue
            e_r = abs(d.r - d.r_target)
            e_theta = abs(angle_wrap(d.theta - d.theta_target))
            # tolerances: radial 0.1 m, angular 0.05 rad ~ 3 degrees
            if e_r > 0.1 or e_theta > 0.05:
                all_done = False
                break
        if all_done:
            # switch RECALIB drones back to ORBIT
            for d in self.drones.values():
                if d.mode == "RECALIB":
                    d.mode = "ORBIT"
            self.recalib_in_progress = False
            print("[Leader] Recalibration complete -> drones RESUME ORBIT.")

    # -------- JOIN protocol (robust) --------

    def handle_join_request(self, new_drone_id: int, t: float):
        """
        Accept a join request: reserve (future_slots) for the new drone and notify current drones.
        Does not immediately spawn the drone — spawn is performed later by spawn_actual_joining_drone().
        """
        # cluster max capacity check
        if len(self.drones) >= 6:
            print("[JOIN] Cannot accept join: cluster already at max size (6 drones).")
            return

        # only one pending join allowed at a time in this simple protocol
        if self.pending_join_id is not None:
            print("[JOIN] Join already pending, ignoring new request.")
            return

        # set pending join metadata
        self.pending_join_id = new_drone_id
        self.pending_join_time = t

        # compute the future set of ids including the new joining id
        current_ids = sorted(self.drones.keys())
        all_ids = sorted(current_ids + [new_drone_id])
        Np = len(all_ids)

        # compute radius for future formation (respecting minimum spacing)
        r_base = self.building_radius + self.margin
        if Np > 1:
            r_safe = self.d_safe / (2 * math.sin(math.pi / Np))
        else:
            r_safe = r_base
        r_future = max(r_base, r_safe)
        delta_theta = 2 * math.pi / Np

        # reserve each future slot (even for the pending join id) in a dict
        self.future_slots = {}
        for i, d_id in enumerate(all_ids):
            theta_star = self.theta0 + i * delta_theta
            self.future_slots[d_id] = (r_future, angle_wrap(theta_star))

        # tell current drones their reserved future targets (so they can prepare)
        for d_id, d in self.drones.items():
            fr, ft = self.future_slots[d_id]
            d.future_r_target = fr
            d.future_theta_target = ft
            d.waiting_for_recalib = True

        # informative log
        print(
            f"[JOIN] Leader accepted join of drone {new_drone_id} at t={t:.1f}s. "
            f"Future N={Np}, r_future={r_future:.2f}. Drones WAIT for GO."
        )

    def start_recalibration_for_join(self, t: float):
        """
        When leader decides to start the recalibration for a pending join,
        copy the reserved future slots into current targets and kick RECALIB mode.
        """
        if self.pending_join_id is None or not self.future_slots:
            print("[JOIN] No pending join to start recalibration for.")
            return

        # set each drone's current target to the reserved future slot and start RECALIB
        for d_id, d in self.drones.items():
            if d_id in self.future_slots:
                fr, ft = self.future_slots[d_id]
                d.r_target = fr
                d.theta_target = ft
                d.mode = "RECALIB"
                d.waiting_for_recalib = False

        # log the assigned coordinates
        print("[Leader] Broadcasted new coordinates to drones for JOIN recalibration (future formation):")
        for d_id, (fr, ft) in self.future_slots.items():
            if d_id in self.drones:
                print(f"    Drone {d_id}: r_target={fr:.2f}, theta_target={ft:.2f}")

        # update radius and mark recalibration in progress
        any_slot = next(iter(self.future_slots.values()))
        self.r_current = any_slot[0]
        self.recalib_in_progress = True
        print(f"[JOIN] GO_RECALIBRATE at t={t:.1f}s for future formation.")

    def handle_join_timeout_if_needed(self, t: float):
        """
        If a pending join was accepted but not completed within join_timeout,
        force an election and push future_slots into active RECALIB so cluster rebalances.
        """
        if self.pending_join_id is None or self.pending_join_time is None:
            return
        if (t - self.pending_join_time) < self.join_timeout:
            return

        # timout occurred — elect and force recalibration based on future_slots
        print(
            f"[JOIN] TIMEOUT for pending drone {self.pending_join_id} at t={t:.1f}s. "
            "Election + forced recalibration from future_slots."
        )

        self.elect_leader(t, reason="join_timeout")

        if not self.future_slots:
            return

        for d_id, d in self.drones.items():
            if d_id in self.future_slots:
                fr, ft = self.future_slots[d_id]
                d.r_target = fr
                d.theta_target = ft
                d.mode = "RECALIB"
                d.waiting_for_recalib = False

        # log the forced recalibration coordinates
        print("[Leader] Broadcasted new coordinates to drones after JOIN TIMEOUT (using future_slots):")
        for d_id, (fr, ft) in self.future_slots.items():
            if d_id in self.drones:
                print(f"    Drone {d_id}: r_target={fr:.2f}, theta_target={ft:.2f}")

        any_slot = next(iter(self.future_slots.values()))
        self.r_current = any_slot[0]
        self.recalib_in_progress = True

        # clear pending join timestamp (join timeout handled)
        self.pending_join_time = None

    def spawn_actual_joining_drone(self, base_world_pos: Tuple[float, float, float]):
        """
        Physically create the new drone in the simulation at the base station,
        command it to fly to its reserved slot, and add it to self.drones.
        """
        if self.pending_join_id is None or not self.future_slots:
            print("[JOIN] No pending join / future slots to realize.")
            return
        new_id = self.pending_join_id
        if new_id in self.drones:
            print("[JOIN] Pending join ID already in cluster.")
            return

        # reserved slot for the joining id
        fr, ft = self.future_slots[new_id]
        # create DronePB starting at base and command it to fly to reserved slot
        new_drone = DronePB(
            drone_id=new_id,
            client_id=self.client_id,
            r=fr,
            theta=ft,
            altitude=self.drone_altitude,
            building_center=self.building_center,
            base_world_pos=base_world_pos,
            start_at_base=True,
        )
        new_drone.battery = 100.0
        new_drone.go_from_base_to_orbit(fr, ft)

        # add to active drones mapping
        self.drones[new_id] = new_drone
        print(
            f"[JOIN] New drone {new_id} spawned at BASE, flying to RESERVED SLOT "
            f"(r={fr:.1f}, theta={ft:.2f})."
        )

        # Redistribute Shamir shares to include new drone
        self.auth_module.on_drone_added(list(self.drones.keys()))

        # clear pending join id (spawn completed)
        self.pending_join_id = None

    # -------- Leave handling --------

    def remove_drone(self, drone_id: int):
        """
        Physically remove a drone from the simulation and update cluster bookkeeping.
        Handles the special case where the removed drone was the leader.
        """
        if drone_id in self.drones:
            d = self.drones[drone_id]
            d.remove_from_world()
            del self.drones[drone_id]
            print(f"[LEAVE] Drone {drone_id} removed from cluster.")
            
            # Redistribute Shamir shares among remaining drones
            if self.drones:
                self.auth_module.on_drone_removed(list(self.drones.keys()))
            
            if self.current_leader_id == drone_id:
                print("[LEAVE] Removed drone was leader -> leader reset.")
                self.last_failed_leader_id = drone_id
                self.current_leader_id = None
            # if we still have a leader after removal, recompute formation;
            # otherwise defer formation recompute until a new leader is elected.
            if self.current_leader_id is not None:
                self.recompute_formation_current()
            else:
                print("[LEAVE] No leader present; formation recomputation deferred.")

    # -------- Leader colors + marker --------

    def _update_leader_colors(self):
        """Color the current leader yellow and followers green for easy visualization."""
        for d_id, d in self.drones.items():
            if d_id == self.current_leader_id:
                d.set_color([1.0, 1.0, 0.0, 1.0])  # yellow leader
            else:
                d.set_color([0.1, 0.8, 0.1, 1.0])  # green follower

    def _ensure_leader_sphere_exists(self):
        """Create a translucent sphere used to mark the leader in the world (if missing)."""
        if self.leader_sphere_id is not None:
            return
        radius = 2.0
        vis_shape = p.createVisualShape(
            p.GEOM_SPHERE,
            radius=radius,
            rgbaColor=[1.0, 1.0, 0.0, 0.25],
            physicsClientId=self.client_id,
        )
        self.leader_sphere_id = p.createMultiBody(
            baseMass=0.0,
            baseCollisionShapeIndex=-1,
            baseVisualShapeIndex=vis_shape,
            basePosition=[0, 0, -100],  # hidden initially
            baseOrientation=p.getQuaternionFromEuler([0, 0, 0]),
            physicsClientId=self.client_id,
        )

    def _update_leader_marker(self):
        """Place the leader sphere at the leader drone's position; hide it if no leader."""
        if self.current_leader_id is None or self.current_leader_id not in self.drones:
            # hide the leader marker offscreen
            if self.leader_sphere_id is not None:
                p.resetBasePositionAndOrientation(
                    self.leader_sphere_id,
                    [0, 0, -100],
                    p.getQuaternionFromEuler([0, 0, 0]),
                    physicsClientId=self.client_id,
                )
            # remove any debug text if present
            if self.leader_debug_id is not None:
                try:
                    p.removeUserDebugItem(self.leader_debug_id, physicsClientId=self.client_id)
                except Exception:
                    pass
                self.leader_debug_id = None
            return

        # ensure exists and position it above the leader drone
        self._ensure_leader_sphere_exists()
        ld = self.drones[self.current_leader_id]
        pos = [ld.x, ld.y, ld.z]

        p.resetBasePositionAndOrientation(
            self.leader_sphere_id,
            pos,
            p.getQuaternionFromEuler([0, 0, 0]),
            physicsClientId=self.client_id,
        )

        # clear debug id if present
        if self.leader_debug_id is not None:
            try:
                p.removeUserDebugItem(self.leader_debug_id, physicsClientId=self.client_id)
            except Exception:
                pass
            self.leader_debug_id = None

    # -------- Link quality & leader score update --------

    def _update_link_quality_and_scores(self, reason: str):
        """
        1) Compute link_quality for each drone as the average received signal strength
           from neighbors (clipped to [0,1] and with small sensor noise).
        2) Set leader_confidence for each drone based on the reason for election.
        3) Compute a final leader_score as a weighted combination of battery, link quality,
           and leader confidence. This score is used in the election routine.
        """
        ids = list(self.drones.keys())
        if not ids:
            return

        # ---- 1) Compute link_quality for each drone (same as before) ----
        for i in ids:
            di = self.drones[i]
            total_sig = 0.0
            count = 0
            xi, yi, zi = di.x, di.y, di.z

            # measure signal to every other drone and average those within comm_range
            for j in ids:
                if j == i:
                    continue
                dj = self.drones[j]
                xj, yj, zj = dj.x, dj.y, dj.z
                dx = xj - xi
                dy = yj - yi
                dz = zj - zi
                dist = math.sqrt(dx * dx + dy * dy + dz * dz)

                # simple linear signal model: 1.0 at 0m, 0.0 at comm_range
                if dist <= self.comm_range:
                    sig = max(0.0, 1.0 - dist / self.comm_range)
                    # simulate small measurement noise
                    sig += random.uniform(-0.05, 0.05)
                    # clamp to [0,1]
                    sig = min(1.0, max(0.0, sig))
                    total_sig += sig
                    count += 1

            # average neighboring signals to obtain a single link_quality metric
            di.link_quality = total_sig / count if count > 0 else 0.0

        # ---- 2) Set leader_confidence with RANDOMIZED offsets per drone ----
        def _randomized_conf(base: float) -> float:
            # small random variation around base, clamped to [0, 1]
            return max(0.0, min(1.0, base + random.uniform(-0.15, 0.15)))

        # choose base confidence depending on why election is running
        for d in self.drones.values():
            if reason in ("failure_or_no_leader", "leader_missing"):
                # when leader missing/failure — each drone is very confident
                d.leader_confidence = _randomized_conf(1.0)
            elif reason == "join_timeout":
                d.leader_confidence = _randomized_conf(0.8)
            elif reason == "low_battery":
                d.leader_confidence = _randomized_conf(0.4)
            elif reason == "periodic":
                d.leader_confidence = _randomized_conf(0.2)
            else:
                d.leader_confidence = _randomized_conf(0.3)

        # ---- 3) Compute final leader_score with updated confidence ----
        for d in self.drones.values():
            # normalize battery to [0,1]
            battery_norm = max(0.0, min(1.0, d.battery / 100.0))
            # weighted combination -> overall leader quality score
            d.leader_score = (
                0.5 * battery_norm
                + 0.3 * d.link_quality
                + 0.2 * d.leader_confidence
            )

    # -------- Timer-based Ring Leader Election (score-based) --------

    def _timer_ring_election(
        self,
        rcp_id: int,
        initiator_ids: List[int],
        scores: Dict[int, float],
    ) -> int:
        """
        Ring-based message-passing election simulation.
        - ring: sorted list of drone ids used as positions for token passing.
        - initiator_ids: drones that start by injecting their candidate message into the ring.
        - scp_id[pid], scp_score[pid] represent the stored best candidate for ring position `pid`.
        The algorithm circulates messages; when a message returns to its origin and remains best,
        that candidate wins. Tie-breaks use lower id by design in this implementation.
        """
        if not self.drones:
            return None

        # deterministic ring order (ascending drone ids)
        ring: List[int] = sorted(self.drones.keys())
        n = len(ring)

        # scp = stored candidate id / score per ring position
        scp_id: Dict[int, int] = {}
        scp_score: Dict[int, float] = {}

        # initialize stored candidate for each ring slot to rcp_id sentinel
        for pid in ring:
            scp_id[pid] = rcp_id
            scp_score[pid] = -1.0

        # message queue: each message carries cand_id, cand_score, idx (ring index)
        messages: List[Dict[str, float]] = []

        # Seed the queue with all initiator candidate messages
        for mcp_id in initiator_ids:
            if mcp_id not in self.drones:
                continue
            cand_score = scores.get(mcp_id, 0.0)
            # initialize stored candidate at that slot to the candidate itself
            scp_id[mcp_id] = mcp_id
            scp_score[mcp_id] = cand_score
            idx = ring.index(mcp_id)
            messages.append({
                "cand_id": mcp_id,
                "cand_score": cand_score,
                "idx": idx,
            })

        # If no messages were seeded, fallback to selecting the highest-scoring id directly.
        if not messages:
            if not scores:
                return max(ring)
            return max(scores, key=scores.get)

        # safety-bound to avoid infinite loops: proportional to n and number of messages
        max_iterations = 10 * n * max(1, len(messages))
        iterations = 0

        # process messages until convergence or iteration cap
        while messages and iterations < max_iterations:
            iterations += 1

            # pop the next message and forward it one step
            msg = messages.pop(0)
            cand_id = msg["cand_id"]
            cand_score = msg["cand_score"]

            next_idx = (int(msg["idx"]) + 1) % n
            msg["idx"] = next_idx
            pid = ring[next_idx]  # the drone id at the next ring position

            pid_scp_id = scp_id[pid]
            pid_scp_score = scp_score[pid]

            # If the stored candidate at pid is the default sentinel (rcp_id),
            # accept the incoming candidate and keep forwarding it.
            if pid_scp_id == rcp_id:
                scp_id[pid] = cand_id
                scp_score[pid] = cand_score
                messages.append(msg)
            else:
                # Otherwise we compare incoming candidate against the stored one
                better_msg = False
                if cand_score > pid_scp_score:
                    better_msg = True
                elif math.isclose(cand_score, pid_scp_score, rel_tol=1e-3):
                    # tie-break: prefer lower numeric id in this implementation
                    if cand_id < pid_scp_id:
                        better_msg = True

                if better_msg:
                    scp_id[pid] = cand_id
                    scp_score[pid] = cand_score
                    messages.append(msg)

            # If the message has returned to its own slot and is still the stored candidate,
            # and it is not the sentinel, it wins.
            if pid == cand_id and scp_id[pid] == cand_id and cand_id != rcp_id:
                return cand_id

        # If loop ended, pick the best id from scp_score (tie-breaks favor lower id due to sorted ring)
        if scp_score:
            best_id = max(scp_score, key=scp_score.get)
            return best_id

        # final fallback: choose max id in ring (should not normally happen)
        return max(ring)

    # -------- Leader Election --------

    def elect_leader(self, t: float, reason: str = "unspecified"):
        """
        Top-level election routine:
        - compute updated link qualities and scores,
        - optionally forbid a recently failed leader,
        - choose a set of initiators and run the ring-election,
        - finalize the new current_leader_id and update visuals.
        """
        if not self.drones:
            self.current_leader_id = None
            return

        # recompute per-drone metrics used in the scoring function
        self._update_link_quality_and_scores(reason)
        scores = {d_id: d.leader_score for d_id, d in self.drones.items()}

        # If a recent leader failed, mark it as forbidden by setting a very low score.
        failure_reasons = ("failure_or_no_leader", "leader_missing", "join_timeout")
        forbidden_id = None
        if reason in failure_reasons and self.last_failed_leader_id in self.drones:
            forbidden_id = self.last_failed_leader_id
            scores[forbidden_id] = -1.0

        # Print diagnostics so the user sees the election inputs
        print("\n[Election] ================================")
        print(f"[Election] reason = {reason}, t = {t:.1f}s")
        for d_id in sorted(self.drones.keys()):
            d = self.drones[d_id]
            print(
                f"[Election]  Drone {d_id}: "
                f"score={d.leader_score:.3f}, "
                f"batt={d.battery:.1f}%, "
                f"link={d.link_quality:.3f}, "
                f"conf={d.leader_confidence:.2f}"
            )

        # rcp_id: sentinel used by the ring algorithm (current leader id or -1)
        rcp_id = self.current_leader_id if self.current_leader_id is not None else -1
        all_ids = sorted(self.drones.keys())

        # Build candidate list excluding forbidden id if necessary
        if forbidden_id is not None and len(all_ids) > 1:
            candidate_ids = [i for i in all_ids if i != forbidden_id]
        else:
            candidate_ids = all_ids[:]
        if not candidate_ids:
            candidate_ids = all_ids[:]

        # choose initiator ids (here we use all candidates; could be subset)
        if reason in ("failure_or_no_leader", "leader_missing", "join_timeout", "periodic", "low_battery"):
            initiator_ids = candidate_ids
        else:
            initiator_ids = candidate_ids
        if not initiator_ids:
            initiator_ids = all_ids[:]

        print(f"[Election] Initiators: {initiator_ids}")

        # run the ring-based election and get the elected drone id
        elected = self._timer_ring_election(
            rcp_id=rcp_id,
            initiator_ids=initiator_ids,
            scores=scores,
        )

        # if the elected id happens to be the forbidden one, pick best among remaining candidates
        if (
            forbidden_id is not None
            and elected == forbidden_id
            and len(candidate_ids) > 0
        ):
            alt_candidates = {cid: scores.get(cid, -1e9) for cid in candidate_ids}
            elected = max(alt_candidates, key=alt_candidates.get)

        # Prepare logging of old leader for better traceability in logs
        if self.current_leader_id is None and forbidden_id is not None and reason in failure_reasons:
            old_leader_for_log = forbidden_id
        else:
            old_leader_for_log = self.current_leader_id

        old_leader = old_leader_for_log
        # set the new leader and update visuals
        self.current_leader_id = elected
        self.last_election_time = t
        self._update_leader_colors()

        # reset periodic counters and set new reference drone for orbit tracking
        self.rounds_since_last_election = 0
        self.orbit_unwrapped = 0.0
        self.prev_theta_ref = None
        self.reference_id = min(self.drones.keys()) if self.drones else None

        # print result - either changed or remained
        if old_leader != elected:
            print(
                f"[Election] RESULT: New leader = Drone {elected} "
                f"(old leader={old_leader})"
            )
        else:
            print(
                f"[Election] RESULT: Leader remains Drone {elected} "
                f"(no change)"
            )
        print("[Election] =================================\n")

    # -------- Orbit round tracking for periodic re-election --------

    def _update_orbit_rounds(self):
        """
        Track angular progress of a reference drone and count complete rounds.
        After a threshold number of rounds, the leader may trigger a periodic re-election.
        """
        if not self.drones:
            return
        if self.reference_id not in self.drones:
            # if reference missing, pick the smallest id present
            self.reference_id = min(self.drones.keys())
            self.prev_theta_ref = None
            self.orbit_unwrapped = 0.0
            return

        ref = self.drones[self.reference_id]
        # only track if reference is in ORBIT or RECALIB (has meaningful theta)
        if ref.mode not in ("ORBIT", "RECALIB"):
            return

        theta = ref.theta
        if self.prev_theta_ref is None:
            self.prev_theta_ref = theta
            return

        # unwrap positive angular movement only
        dtheta = angle_wrap(theta - self.prev_theta_ref)
        self.prev_theta_ref = theta

        if dtheta > 0:
            self.orbit_unwrapped += dtheta

        two_pi = 2.0 * math.pi
        # for every full 2*pi rotation, increment rounds counter
        while self.orbit_unwrapped >= two_pi:
            self.orbit_unwrapped -= two_pi
            self.rounds_since_last_election += 1
            print(f"[Periodic] Reference drone completed round #{self.rounds_since_last_election}")

    def maybe_run_election(self, t: float):
        """
        Decide whether to trigger an election based on:
        - suppressed intervals (scripted buffers),
        - missing leader or leader missing from drones,
        - periodic round threshold,
        - low battery on current leader.
        """
        if self.auto_election_suppressed_until is not None:
            if t < self.auto_election_suppressed_until:
                return
            else:
                self.auto_election_suppressed_until = None

        if not self.drones:
            self.current_leader_id = None
            return

        # if no leader or leader disappeared -> immediate election
        if self.current_leader_id is None or self.current_leader_id not in self.drones:
            self.elect_leader(t, reason="failure_or_no_leader")
            return

        leader_drone = self.drones.get(self.current_leader_id, None)
        if leader_drone is None:
            self.elect_leader(t, reason="leader_missing")
            return

        # periodic re-election if enough rounds completed
        if self.rounds_since_last_election >= self.periodic_rounds_threshold:
            self.elect_leader(t, reason="periodic")
            return

        # leader battery low -> trigger re-election
        if leader_drone.battery <= self.low_battery_threshold:
            self.elect_leader(t, reason="low_battery")

    # -------- Main step --------

    def step(self, dt: float, t: float, base_world_pos: Tuple[float, float, float]):
        """
        Per-frame cluster update:
        - step each drone physics/controller,
        - handle join timeout,
        - remove drones that reached base,
        - detect end of recalibration and resume orbit,
        - update orbit rounds and possibly run election,
        - update visual leader marker.
        """
        # step each drone (they update positions and modes internally)
        for d in self.drones.values():
            d.step(dt)

        # handle a pending join that exceeded timeout (may force election + recalib)
        self.handle_join_timeout_if_needed(t)

        # remove drones that have reached AT_BASE (finalize leave)
        to_remove = [d_id for d_id, d in self.drones.items() if d.mode == "AT_BASE"]
        for d_id in to_remove:
            self.remove_drone(d_id)

        # if recalibration in progress, check if it finished
        self._finish_recalibration_if_done()

        # update orbit round counters (used for periodic re-election)
        self._update_orbit_rounds()

        # maybe run election due to periodic threshold, low battery, or missing leader
        self.maybe_run_election(t)

        # update leader sphere / colors in the visualization
        self._update_leader_marker()


# =========================
# Environment Setup
# =========================

def create_building(
    client_id: int,
    radius: float,
    height: float,
    center=(0.0, 0.0),
):
    """
    Create a cylindrical building in PyBullet at center with given radius/height.
    Visual only (static, zero mass).
    """
    cx, cy = center
    col_shape = p.createCollisionShape(
        p.GEOM_CYLINDER, radius=radius, height=height, physicsClientId=client_id
    )
    vis_shape = p.createVisualShape(
        p.GEOM_CYLINDER,
        radius=radius,
        length=height,
        rgbaColor=[0.6, 0.6, 0.9, 1.0],
        physicsClientId=client_id,
    )
    base_z = height / 2.0
    base_pos = [cx, cy, base_z]
    base_orn = p.getQuaternionFromEuler([0, 0, 0])

    return p.createMultiBody(
        baseMass=0.0,
        baseCollisionShapeIndex=col_shape,
        baseVisualShapeIndex=vis_shape,
        basePosition=base_pos,
        baseOrientation=base_orn,
        physicsClientId=client_id,
    )


def create_base_station(client_id: int, position=(50.0, 0.0, 0.0)):
    """
    Create a simple box to serve as a base station (spawn/land area for drones).
    """
    x, y, z = position
    half = [2.0, 2.0, 0.2]
    col_shape = p.createCollisionShape(
        p.GEOM_BOX, halfExtents=half, physicsClientId=client_id
    )
    vis_shape = p.createVisualShape(
        p.GEOM_BOX,
        halfExtents=half,
        rgbaColor=[0.1, 0.1, 0.8, 1.0],
        physicsClientId=client_id,
    )
    base_pos = [x, y, z + half[2]]
    base_orn = p.getQuaternionFromEuler([0, 0, 0])
    p.createMultiBody(
        baseMass=0.0,
        baseCollisionShapeIndex=col_shape,
        baseVisualShapeIndex=vis_shape,
        basePosition=base_pos,
        baseOrientation=base_orn,
        physicsClientId=client_id,
    )


def main():
    """
    Main entry point:
    - initialize PyBullet and the environment,
    - create initial drones and ClusterLeader,
    - provide keyboard controls to trigger join/leave scenarios,
    - run the simulation loop until the GUI is closed.
    """
    try:
        print("\n[INIT] Starting Shamir Drone Swarm Simulation...")
        print("[INIT] Initializing PyBullet in DIRECT mode (no GUI - stable)...")
        
        # USE DIRECT MODE - NO GUI - WON'T CRASH
        client_id = p.connect(p.DIRECT)
        print(f"[INIT] ✅ PyBullet connected in DIRECT mode (client_id={client_id})")
        
        is_gui_mode = False  # No GUI
        
        p.setAdditionalSearchPath(pybullet_data.getDataPath())
        p.setGravity(0, 0, -9.8, physicsClientId=client_id)
        p.loadURDF("plane.urdf", physicsClientId=client_id)
        print("[INIT] ✅ Environment loaded (plane, gravity)")
        
        # building and base setup
        building_radius = 10.0
        building_height = 20.0
        building_center = (0.0, 0.0)
        create_building(client_id, building_radius, building_height, building_center)
        print("[INIT] ✅ Building created")
        
        base_world_pos = (50.0, 0.0, 0.2)
        create_base_station(client_id, base_world_pos)
        print("[INIT] ✅ Base station created")
        
        print("[INIT] ✅ Running in DIRECT mode (no visualization)")
    except Exception as e:
        print(f"[ERROR] Failed during initialization: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
        return

    # --- No GUI controls in DIRECT mode ---
    # Set all GUI variables to None
    cam_yaw_slider = None
    cam_pitch_slider = None
    cam_dist_slider = None
    cam_target_x_slider = None
    cam_target_y_slider = None
    cam_target_z_slider = None
    test_fake_drone_button = None
    test_real_drone_button = None
    fake_drone_type_slider = None
    last_fake_button_value = None
    last_real_button_value = None
    fake_types = ["invalid_signature", "expired_cert", "tampered_cert", "old_timestamp"]
    print("[INIT] ✅ Running without GUI - automatic tests will run")

    # Ensure drones fly ABOVE the building height to avoid collisions with building top
    drone_altitude = building_height + 5.0  # 25.0 here

    # Create initial drone set (ids 1..initial_N)
    try:
        print("[INIT] Creating initial drone swarm...")
        drones: Dict[int, DronePB] = {}
        initial_N = 5
        r_init = building_radius + 25.0
        for i in range(initial_N):
            theta = 2 * math.pi * i / initial_N
            d = DronePB(
                drone_id=i + 1,
                client_id=client_id,
                r=r_init,
                theta=theta,
                altitude=drone_altitude,
                building_center=building_center,
                base_world_pos=base_world_pos,
                start_at_base=False,
            )
            drones[d.id] = d
            print(f"[INIT]   Drone {d.id} created at position ({d.x:.1f}, {d.y:.1f}, {d.z:.1f})")
        print(f"[INIT] ✅ {initial_N} drones created successfully")
    except Exception as e:
        print(f"[ERROR] Failed creating drones: {e}")
        import traceback
        traceback.print_exc()
        return

    # Create the logical cluster leader that manages formation and elections
    try:
        print("[INIT] Initializing ClusterLeader with Shamir authentication...")
        leader = ClusterLeader(
            client_id=client_id,
            drones=drones,
            building_radius=building_radius,
            margin=15.0,
            d_safe=8.0,
            theta0=0.0,
            building_center=building_center,
            drone_altitude=drone_altitude,
            election_interval=25.0,
            low_battery_threshold=30.0,
            join_timeout=6.0,
            comm_range=60.0,
            shamir_k_threshold=3,  # K-of-N threshold for Shamir authentication
        )
        print("[INIT] ✅ ClusterLeader initialized")
    except Exception as e:
        print(f"[ERROR] Failed initializing ClusterLeader: {e}")
        import traceback
        traceback.print_exc()
        return

    # compute initial formation (sets RECALIB for all to move into desired slots)
    try:
        print("[INIT] Computing initial formation...")
        leader.recompute_formation_current()
        print("[INIT] ✅ Formation computed")
    except Exception as e:
        print(f"[ERROR] Failed computing formation: {e}")
        import traceback
        traceback.print_exc()
        return
        
    # run initial election to choose a leader at t=0
    try:
        print("[INIT] Running initial leader election...")
        leader.elect_leader(t=0.0, reason="initial")
        print("[INIT] ✅ Leader elected")
    except Exception as e:
        print(f"[ERROR] Failed leader election: {e}")
        import traceback
        traceback.print_exc()
        return

    # Scenario state dictionaries used by keyboard controls to orchestrate multi-step cases
    scenario1 = {
        "active": False,
        "failed": False,
        "spawned": False,
        "join_id": None,
        "fail_time": None,
        "buffer_end": None,
        "spawn_time": None,
    }

    scenario3 = {
        "active": False,
        "leader_failed": False,
        "leave_id": None,
        "fail_time": None,
        "buffer_end": None,
        "reformed": False,
    }

    # Print help for interactive controls
    print(
        "\n[Controls]\n"
        "  KEYBOARD:\n"
        "  1: Secure Join + leader fails + base-triggered re-election\n"
        "  2: Secure Normal join (with Shamir authentication)\n"
        "  3: Leave + leader fails + re-election\n"
        "  4: Force periodic re-election (manual)\n"
        "  5: Immediate leader failure re-election\n"
        "  6: Normal leave (no failure)\n"
        "  (If no key pressed, swarm orbits as normal; auto periodic after 3 rounds.)\n"
        "\n  GUI TESTING BUTTONS:\n"
        "  🧪 'Test Fake Drone': Send malicious drone (should be REJECTED)\n" 
        "  ✅ 'Test Real Drone': Send legitimate drone (should be ACCEPTED)\n"
        "  'Fake Type' slider: Choose fake drone attack type:\n"
        "    0 = Invalid signature\n"
        "    1 = Expired certificate\n" 
        "    2 = Tampered certificate\n"
        "    3 = Old timestamp (replay attack)\n"
        "\n[Shamir Secret Sharing Authentication]\n"
        "  - Each existing drone holds one Shamir secret share\n"
        "  - Leader selects K=3 trusted drones to reconstruct master secret\n"
        "  - Challenge = H(secret || Drone_ID || nonce)\n"
        "  - Joining drone signs challenge to prove legitimacy\n"
        "  - Failed authentication → drone blacklisted\n"
        "  - Use GUI buttons to test authentication robustness!\n"
    )

    # time step for simulation loop (~60Hz)
    dt = 1.0 / 60.0
    t = 0.0

    print("\n" + "="*70)
    print("[INIT] ✅✅✅ SIMULATION READY ✅✅✅")
    print("="*70)
    print("[INFO] Running in DIRECT mode (no visualization)")
    print("[INFO] Automatic authentication tests will run")
    print("[INFO] Watch terminal for Shamir authentication process")
    print("="*70 + "\n")

    # Auto-test scheduling
    test_schedule = [
        (5.0, "real"),      # Test real drone at 5 seconds
        (10.0, "fake_0"),   # Test fake drone (invalid sig) at 10 seconds
        (15.0, "real"),     # Test real drone at 15 seconds
        (20.0, "fake_1"),   # Test fake drone (expired cert) at 20 seconds
        (25.0, "fake_2"),   # Test fake drone (tampered cert) at 25 seconds
        (30.0, "fake_3"),   # Test fake drone (old timestamp) at 30 seconds
        (35.0, "done"),     # End simulation
    ]
    next_test_index = 0

    # --------------------------
    # Main simulation loop
    # --------------------------
    try:
        while p.isConnected(physicsClientId=client_id):
            # No keyboard in DIRECT mode
            keys = {}
            
            # Skip camera updates in DIRECT mode
            
            # Skip button handling in DIRECT mode
        
            # Scheduled automatic tests
            if next_test_index < len(test_schedule):
                test_time, test_type = test_schedule[next_test_index]
                if t >= test_time:
                    print(f"\n[SCHEDULED TEST] t={t:.1f}s - Running: {test_type}")
                    
                    if test_type == "real":
                        if len(leader.drones) < 6:
                            test_real_drone_authentication(leader, t)
                            # Start recalibration if join succeeded
                            if leader.pending_join_id is not None:
                                leader.start_recalibration_for_join(t)
                                leader.spawn_actual_joining_drone(base_world_pos)
                        else:
                            print("[TEST] Swarm at max capacity, skipping real drone test")
                    elif test_type.startswith("fake_"):
                        fake_idx = int(test_type.split("_")[1])
                        test_fake_drone_authentication(leader, t, fake_types[fake_idx])
                    elif test_type == "done":
                        print("\n" + "="*70)
                        print("[SIMULATION] ALL TESTS COMPLETED!")
                        print("="*70)
                        print("[SUMMARY]")
                        print(f"  - Final swarm size: {len(leader.drones)}")
                        print(f"  - Current leader: Drone {leader.current_leader_id}")
                        print(f"  - Blacklisted drones: {leader.auth_module.blacklist}")
                        print("="*70)
                        break
                    
                    next_test_index += 1

            # --------------------------
            # Skip keyboard scenarios in DIRECT mode - go straight to step
            # --------------------------

            # Advance cluster state (drone steps, election checks, removal, visuals)
            leader.step(dt, t, base_world_pos)

            # Step pybullet physics & wait for wall-clock time to keep real-time pacing
            p.stepSimulation(physicsClientId=client_id)
            time.sleep(dt)
            t += dt
            
            # Print progress every 5 seconds
            if int(t * 10) % 50 == 0:
                print(f"[SIM] t={t:.1f}s - Swarm size: {len(leader.drones)}, Leader: Drone {leader.current_leader_id}")
                
    except KeyboardInterrupt:
        print("\n[INFO] Simulation stopped by user (Ctrl+C)")
    except Exception as e:
        print(f"\n[ERROR] Simulation crashed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("[INFO] Cleaning up and closing...")
        try:
            p.disconnect(physicsClientId=client_id)
        except:
            pass
        print("[INFO] Simulation ended")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[CRASH] Error: {e}")
        import traceback
        traceback.print_exc()
        input("\n[CRASH] Press Enter to close this window...")
    finally:
        input("\nPress Enter to exit...")
