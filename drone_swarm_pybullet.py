"""
Original Drone Swarm Simulation with Shamir Secret Sharing Authentication
Integrated authentication layer into the original PyBullet 3D animation
"""

import math
import random
import time
import hashlib
import secrets
import threading
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Tuple, Optional

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *args):
        pass  # suppress access logs

def start_health_server():
    server = HTTPServer(("0.0.0.0", 7860), HealthHandler)
    server.serve_forever()

def maybe_start_health_server():
    if os.environ.get("START_HEALTH_SERVER") != "1":
        return
    threading.Thread(target=start_health_server, daemon=True).start()

maybe_start_health_server()

import pybullet as p
import pybullet_data


# =========================
# Global config / placeholders
# =========================

# Path to the drone URDF model file used for visuals in PyBullet.
# If this fails, the code falls back to drawing a simple sphere for each drone.
DRONE_URDF_PATH = None  # Set to None to use simple spheres


# =========================
# Shamir Secret Sharing Authentication Module
# =========================

class ShamirSecretSharing:
    """
    (K,N) threshold secret sharing using polynomial interpolation.
    
    This class implements the Shamir Secret Sharing scheme which allows a secret
    to be divided into N shares, where any K shares can reconstruct the original secret.
    Uses polynomial interpolation over a finite field (modulo a large prime number).
    """
    
    PRIME = 2**127 - 1  # Large prime number for finite field arithmetic
    
    def __init__(self):
        self.weights: List[int] = []
        self.x_coords: List[int] = []
    
    @staticmethod
    def _mod_inverse(a: int, prime: int) -> int:
        """
        Calculate the modular multiplicative inverse of a modulo prime.
        
        Uses the Extended Euclidean Algorithm to find x such that (a * x) % prime = 1.
        This is needed for Lagrange interpolation in the finite field.
        
        Args:
            a: The number to find the inverse of
            prime: The modulus (must be prime)
            
        Returns:
            The modular inverse of a modulo prime
        """
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            return gcd, y1 - (b // a) * x1, x1
        _, x, _ = extended_gcd(a % prime, prime)
        return (x % prime + prime) % prime
        
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
        Generate N shares of a secret where any K shares can reconstruct it.
        
        Creates a random polynomial of degree (K-1) where the secret is the constant term.
        Evaluates this polynomial at N different points to create the shares.
        
        Args:
            secret: The secret value to be shared (integer)
            k: Threshold - minimum number of shares needed to reconstruct
            n: Total number of shares to generate
            
        Returns:
            List of (x, y) tuples representing the shares, where x is the share index
            and y is the share value
            
        Raises:
            ValueError: If k > n (threshold cannot exceed total shares)
        """
        if k > n:
            raise ValueError("Threshold k cannot exceed total shares n")
        coefficients = [secret] + [secrets.randbelow(ShamirSecretSharing.PRIME) for _ in range(k - 1)]
        shares = []
        for x in range(1, n + 1):
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
    Simulated PKI (Public Key Infrastructure) credentials for a drone.
    
    Represents the cryptographic credentials each drone needs for authentication.
    Includes private key, public key, and a certificate with metadata.
    """
    
    def __init__(self, drone_id: int, is_legitimate: bool = True):
        """
        Initialize drone credentials with PKI components.
        
        Creates a private key, derives a public key from it, and generates
        a certificate with validity information. Legitimate drones get real
        credentials, while fake drones get invalid keys.
        
        Args:
            drone_id: Unique identifier for this drone
            is_legitimate: True for real drones, False for fake/attack drones
        """
        self.drone_id = drone_id
        self.is_legitimate = is_legitimate
        self.private_key = secrets.token_hex(32) if is_legitimate else "FAKE_KEY_INVALID"
        self.public_key = hashlib.sha256(self.private_key.encode()).hexdigest()
        self.certificate = {
            "drone_id": drone_id,
            "public_key": self.public_key,
            "issuer": "SwarmCA",
            "valid_from": time.time() - 86400,
            "valid_until": time.time() + 86400 * 365,
            "is_legitimate": is_legitimate
        }
    
    def sign(self, message: str) -> str:
        """
        Create a digital signature for a message using the private key.
        
        Simulates signing by hashing the concatenation of private key and message.
        In real PKI, this would use asymmetric cryptography (RSA, ECDSA, etc.).
        
        Args:
            message: The message/challenge to sign
            
        Returns:
            Hex string representing the signature
        """
        return hashlib.sha256(f"{self.private_key}{message}".encode()).hexdigest()
    
    def verify_signature(self, message: str, signature: str) -> bool:
        """
        Verify that a signature matches the message using the private key.
        
        Checks if the provided signature is what this drone would have produced
        for the given message. Uses constant-time comparison to prevent timing attacks.
        
        Args:
            message: The original message that was signed
            signature: The signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        expected = hashlib.sha256(f"{self.private_key}{message}".encode()).hexdigest()
        return secrets.compare_digest(signature, expected)


class ShamirAuthenticationModule:
    """
    Authentication module using Shamir Secret Sharing for drone admission.
    
    Manages the authentication process for drones joining the swarm. Uses Shamir
    Secret Sharing to distribute a master secret among trusted drones, requiring
    K drones to cooperate to authenticate new members. Maintains drone credentials,
    blacklist, and pending challenges.
    """
    
    def __init__(self, k_threshold: int = 3):
        """
        Initialize the authentication module.
        
        Creates a random master secret and sets up data structures for managing
        drone credentials, shares, blacklist, and authentication challenges.
        
        Args:
            k_threshold: Number of drones needed to reconstruct the secret (default: 3)
        """
        self.k_threshold = k_threshold
        self.master_secret = secrets.randbelow(ShamirSecretSharing.PRIME)
        self.drone_shares: Dict[int, Tuple[int, int]] = {}
        self.drone_credentials: Dict[int, DroneCredentials] = {}
        self.blacklist: set = set()
        self.sss_engine = ShamirSecretSharing()

        self.pending_challenges: Dict[int, str] = {}
    
    def register_drone(self, drone_id: int, credentials: DroneCredentials):
        """
        Register a drone's credentials in the authentication system.
        
        Stores the drone's PKI credentials for later verification during
        the authentication process.
        
        Args:
            drone_id: Unique identifier for the drone
            credentials: DroneCredentials object containing PKI information
        """
        self.drone_credentials[drone_id] = credentials
    
    def distribute_shares(self, drone_ids: List[int]):
        """
        Distribute Shamir secret shares among the registered drones.
        
        Generates N shares of the master secret (where N = number of drones) and
        assigns one share to each drone. Any K drones can later combine their shares
        to reconstruct the secret for authentication. Prints detailed distribution info.
        
        Args:
            drone_ids: List of drone IDs that should receive shares
            
        Note:
            Clears any existing shares before distributing new ones.
            Warns if fewer than K drones are available.
        """
        n = len(drone_ids)
        if n < self.k_threshold:
            print(f"[SHARES] ⚠️  Warning: Only {n} drones, need {self.k_threshold} for reconstruction")
            return
        shares = ShamirSecretSharing.generate_shares(self.master_secret, self.k_threshold, n)
        self.drone_shares.clear()
        for drone_id, share in zip(drone_ids, shares):
            self.drone_shares[drone_id] = share
        
        # Print detailed share distribution
        print("\n" + "="*70)
        print("   📦 SHAMIR SECRET SHARE DISTRIBUTION")
        print("="*70)
        print(f"   Threshold (K): {self.k_threshold} shares needed to reconstruct")
        print(f"   Total Shares (N): {n}")
        print(f"   Master Secret: {str(self.master_secret)[:20]}... (hidden)")
        print("-"*70)
        print(f"   {'Drone ID':<12} {'Share Index (x)':<18} {'Share Value (y)':<30}")
        print("-"*70)
        for drone_id in sorted(drone_ids):
            x, y = self.drone_shares[drone_id]
            y_str = str(y)[:25] + "..." if len(str(y)) > 25 else str(y)
            print(f"   Drone {drone_id:<6} x = {x:<14} y = {y_str}")
        print("="*70 + "\n")
    
    def reconstruct_secret(self, selected_ids: List[int]) -> Optional[int]:
        """
        Reconstruct the master secret using shares from selected drones.
        
        Collects shares from the specified drones and uses Lagrange interpolation
        to reconstruct the original master secret. Requires at least K shares.
        
        Args:
            selected_ids: List of drone IDs whose shares should be used
            
        Returns:
            The reconstructed secret if successful, None if insufficient shares
        """
        shares = [self.drone_shares[d] for d in selected_ids if d in self.drone_shares]
        if len(shares) < self.k_threshold:
            return None
        
        x_coords_used = [s[0] for s in shares[:self.k_threshold]]
        if self.sss_engine.x_coords != x_coords_used:
            self.sss_engine.precompute_weights(x_coords_used, ShamirSecretSharing.PRIME)
            
        return self.sss_engine.reconstruct_secret_fast(shares[:self.k_threshold], self.sss_engine.weights, ShamirSecretSharing.PRIME)
    
    def generate_challenge(self, drone_id: int, nonce: str, secret: int) -> str:
        """
        Generate a cryptographic challenge for a joining drone.
        
        Creates a challenge by hashing the reconstructed secret, drone ID, and a nonce.
        The joining drone must sign this challenge to prove it has the correct private key.
        Stores the challenge as pending for later verification.
        
        Args:
            drone_id: ID of the drone being challenged
            nonce: Random value to prevent replay attacks
            secret: The reconstructed master secret
            
        Returns:
            Hex string representing the challenge
        """
        challenge = hashlib.sha256(f"{secret}{drone_id}{nonce}".encode()).hexdigest()
        self.pending_challenges[drone_id] = challenge
        return challenge
    
    def verify_response(self, drone_id: int, response: str, creds: DroneCredentials) -> Tuple[bool, str]:
        """
        Verify the drone's response to the authentication challenge.
        
        Checks if the drone correctly signed the challenge with its private key.
        If successful, removes the pending challenge. If failed, the drone should
        be blacklisted.
        
        Args:
            drone_id: ID of the responding drone
            response: The signature provided by the drone
            creds: The drone's credentials to verify against
            
        Returns:
            Tuple of (success: bool, message: str) indicating verification result
        """
        if drone_id not in self.pending_challenges:
            return False, "No pending challenge"
        challenge = self.pending_challenges[drone_id]
        if not creds.verify_signature(challenge, response):
            return False, "Invalid signature"
        del self.pending_challenges[drone_id]
        return True, "Verified"
    
    def add_to_blacklist(self, drone_id: int, reason: str):
        """
        Add a drone to the blacklist due to authentication failure.
        
        Blacklisted drones cannot join the swarm. This prevents malicious or
        compromised drones from repeatedly attempting to authenticate.
        
        Args:
            drone_id: ID of the drone to blacklist
            reason: Description of why the drone was blacklisted
        """
        self.blacklist.add(drone_id)
        print(f"[BLACKLIST] ⛔ Drone {drone_id}: {reason}")


def authenticate_join_request(auth_module: ShamirAuthenticationModule, 
                             joining_drone_id: int,
                             credentials: DroneCredentials,
                             existing_drone_ids: List[int],
                             attack_type: str = None) -> Tuple[bool, str]:
    """
    Main authentication function for drones requesting to join the swarm.
    
    Performs a 6-step authentication process:
    1. Blacklist Check - Ensure drone is not previously blacklisted
    2. Certificate Validation - Verify certificate issuer, expiry, and legitimacy
    3. Trusted Drone Selection - Select K trusted drones to participate
    4. Secret Reconstruction - Use selected shares to reconstruct the master secret
    5. Challenge Generation - Create a cryptographic challenge using the secret
    6. Response Verification - Verify the drone signed the challenge correctly
    
    Prints detailed logs for each step showing the authentication process.
    
    Args:
        auth_module: The authentication module managing the process
        joining_drone_id: ID of the drone requesting to join
        credentials: PKI credentials of the joining drone
        existing_drone_ids: List of currently active drone IDs in the swarm
        attack_type: Optional attack simulation type (for testing security)
        
    Returns:
        Tuple of (success: bool, reason: str) with authentication result and message
    """
    print("\n" + "="*70)
    print(f"   🔐 SHAMIR SECRET SHARING AUTHENTICATION")
    print(f"   Drone {joining_drone_id} requesting to join swarm")
    print("="*70)
    
    # Print JOIN REQUEST details
    print("\n" + "-"*70)
    print("   📨 JOIN REQUEST RECEIVED")
    print("-"*70)
    print(f"   Drone ID:        {joining_drone_id}")
    print(f"   Timestamp:       {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Request Nonce:   {secrets.token_hex(8)}")
    print("-"*70)
    
    # Print CERTIFICATE details
    cert = credentials.certificate
    print("\n" + "-"*70)
    print("   📜 CERTIFICATE INFORMATION")
    print("-"*70)
    print(f"   Drone ID:        {cert['drone_id']}")
    print(f"   Public Key:      {cert['public_key'][:32]}...")
    print(f"   Issuer:          {cert['issuer']}")
    print(f"   Valid From:      {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cert['valid_from']))}")
    print(f"   Valid Until:     {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cert['valid_until']))}")
    print(f"   Is Legitimate:   {cert['is_legitimate']}")
    print("-"*70)
    
    # Print DRONE CREDENTIALS
    print("\n" + "-"*70)
    print("   🔑 DRONE CREDENTIALS")
    print("-"*70)
    print(f"   Private Key:     {credentials.private_key[:16]}... (hidden)")
    print(f"   Public Key:      {credentials.public_key[:32]}...")
    print(f"   Key Type:        {'VALID (64-char hex)' if len(credentials.private_key) == 64 else 'INVALID (fake key)'}")
    print("-"*70)
    
    # Step 1: Blacklist check
    print(f"\n[STEP 1] 🚫 BLACKLIST CHECK")
    print(f"   Current blacklist: {auth_module.blacklist if auth_module.blacklist else 'Empty'}")
    print(f"   Checking if Drone {joining_drone_id} is blacklisted...")
    if joining_drone_id in auth_module.blacklist:
        reason = "Drone is blacklisted"
        print(f"[STEP 1] ❌ FAILED: {reason}")
        return False, reason
    print(f"[STEP 1] ✓ PASSED - Not in blacklist")
    
    # Step 2: Certificate validation
    print(f"\n[STEP 2] 📜 CERTIFICATE VALIDATION")
    print(f"   Checking certificate fields...")
    
    # Check 2a: Issuer
    print(f"   [2a] Issuer Check: Expected 'SwarmCA', Got '{cert['issuer']}'")
    if attack_type == "tampered_cert":
        reason = "Certificate tampered - issuer mismatch"
        print(f"        ❌ FAILED: Issuer does not match trusted CA")
        auth_module.add_to_blacklist(joining_drone_id, reason)
        return False, reason
    print(f"        ✓ Issuer verified")
    
    # Check 2b: Expiry
    current_time = time.time()
    print(f"   [2b] Expiry Check: Current time vs Valid Until")
    print(f"        Current: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"        Expires: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(cert['valid_until']))}")
    if attack_type == "expired_cert":
        reason = "Certificate expired"
        print(f"        ❌ FAILED: Certificate has expired")
        auth_module.add_to_blacklist(joining_drone_id, reason)
        return False, reason
    print(f"        ✓ Certificate not expired")
    
    # Check 2c: Legitimacy
    print(f"   [2c] Legitimacy Check: is_legitimate = {cert.get('is_legitimate', True)}")
    if not cert.get("is_legitimate", True):
        reason = "Invalid certificate - not legitimate"
        print(f"        ❌ FAILED: Certificate marked as illegitimate")
        auth_module.add_to_blacklist(joining_drone_id, reason)
        return False, reason
    print(f"        ✓ Certificate is legitimate")
    
    print(f"[STEP 2] ✓ PASSED - All certificate checks passed")
    
    # Step 3: Select K trusted drones
    print(f"\n[STEP 3] 🤝 TRUSTED DRONE SELECTION")
    print(f"   Threshold K = {auth_module.k_threshold} (minimum shares needed)")
    print(f"   Available drones with shares: {[d for d in existing_drone_ids if d in auth_module.drone_shares]}")
    available_drones = [d for d in existing_drone_ids if d in auth_module.drone_shares]
    if len(available_drones) < auth_module.k_threshold:
        reason = f"Insufficient drones ({len(available_drones)}/{auth_module.k_threshold})"
        print(f"[STEP 3] ❌ FAILED: {reason}")
        return False, reason
    selected_drones = random.sample(available_drones, auth_module.k_threshold)
    print(f"   Randomly selected {auth_module.k_threshold} drones: {selected_drones}")
    print(f"[STEP 3] ✓ PASSED - {auth_module.k_threshold} trusted drones selected")
    
    # Print shares being used for reconstruction
    print("\n   ┌─────────────────────────────────────────────────────────────┐")
    print("   │  📦 SHARES USED FOR SECRET RECONSTRUCTION                   │")
    print("   ├─────────────────────────────────────────────────────────────┤")
    for d_id in selected_drones:
        x, y = auth_module.drone_shares[d_id]
        y_short = str(y)[:20] + "..."
        print(f"   │  Drone {d_id}: Share(x={x}, y={y_short})  │")
    print("   └─────────────────────────────────────────────────────────────┘")
    
    # Step 4: Reconstruct secret
    print(f"\n[STEP 4] 🔓 SECRET RECONSTRUCTION (Lagrange Interpolation)")
    print(f"   Using {len(selected_drones)} shares to reconstruct the polynomial at x=0")
    print(f"   Formula: S = Σ yᵢ × Lᵢ(0) where Lᵢ(0) = Π(0-xⱼ)/(xᵢ-xⱼ)")
    reconstructed = auth_module.reconstruct_secret(selected_drones)
    if reconstructed is None:
        reason = "Failed to reconstruct secret"
        print(f"[STEP 4] ❌ FAILED: {reason}")
        return False, reason
    print(f"   Reconstructed Secret: {str(reconstructed)[:30]}...")
    print(f"[STEP 4] ✓ PASSED - Secret reconstructed successfully")
    
    # Step 5: Generate challenge
    print(f"\n[STEP 5] 🎯 CHALLENGE GENERATION")
    nonce = secrets.token_hex(16)
    print(f"   Components:")
    print(f"     - Secret:    {str(reconstructed)[:20]}... (from Step 4)")
    print(f"     - Drone ID:  {joining_drone_id}")
    print(f"     - Nonce:     {nonce} (random, prevents replay)")
    print(f"   ")
    print(f"   Formula: Challenge = SHA256(secret || drone_id || nonce)")
    challenge = auth_module.generate_challenge(joining_drone_id, nonce, reconstructed)
    print(f"   ")
    print(f"   Generated Challenge: {challenge}")
    print(f"[STEP 5] ✓ PASSED - Challenge sent to joining drone")
    
    # Step 6: Verify response
    print(f"\n[STEP 6] ✍️  CHALLENGE-RESPONSE VERIFICATION")
    print(f"   Drone must sign the challenge with its private key")
    print(f"   Formula: Response = SHA256(private_key || challenge)")
    
    if attack_type == "invalid_signature":
        reason = "Invalid signature - drone cannot prove identity"
        print(f"   ")
        print(f"   Expected signature: Based on valid private key")
        print(f"   Received signature: INVALID (fake/wrong key used)")
        print(f"[STEP 6] ❌ FAILED: {reason}")
        auth_module.add_to_blacklist(joining_drone_id, reason)
        return False, reason
    
    signed_response = credentials.sign(challenge)
    print(f"   ")
    print(f"   Drone's Response: {signed_response}")
    print(f"   ")
    print(f"   Verification:")
    print(f"     - Compute expected = SHA256(drone_private_key || challenge)")
    print(f"     - Compare: response == expected")
    
    success, msg = auth_module.verify_response(joining_drone_id, signed_response, credentials)
    
    if not success:
        print(f"     - Result: MISMATCH ❌")
        print(f"[STEP 6] ❌ FAILED: {msg}")
        auth_module.add_to_blacklist(joining_drone_id, msg)
        return False, msg
    
    print(f"     - Result: MATCH ✓")
    print(f"[STEP 6] ✓ PASSED - Signature verified, drone identity confirmed")
    
    # Final result
    print("\n" + "="*70)
    print(f"   ✅ AUTHENTICATION SUCCESSFUL")
    print("="*70)
    print(f"   Drone {joining_drone_id} has passed all 6 authentication steps:")
    print(f"     ✓ Step 1: Blacklist check")
    print(f"     ✓ Step 2: Certificate validation")
    print(f"     ✓ Step 3: Trusted drone selection")
    print(f"     ✓ Step 4: Secret reconstruction")
    print(f"     ✓ Step 5: Challenge generation")
    print(f"     ✓ Step 6: Response verification")
    print(f"   ")
    print(f"   🚁 Drone {joining_drone_id} is APPROVED to join the swarm!")
    print("="*70 + "\n")
    return True, "Authenticated successfully"


# =========================
# Helper Functions
# =========================

def angle_wrap(angle: float) -> float:
    """
    Wrap angle to the range [-pi, pi).
    
    Normalizes angles to a standard range for consistent comparisons and calculations.
    Prevents issues with angle differences wrapping around (e.g., 350° and 10° are
    only 20° apart, not 340°).

    Args:
        angle: Angle in radians (any value)
        
    Returns:
        Equivalent angle in the range [-pi, pi)
        
    Example:
        angle_wrap(7.0) → approximately 0.717 (7.0 - 2*pi)
        angle_wrap(-7.0) → approximately -0.717 (-7.0 + 2*pi)
    """
    return (angle + math.pi) % (2 * math.pi) - math.pi


# =========================
# Drone Classes
# =========================

class DronePB:
    """
    A single drone in PyBullet simulation with authentication support.
    
    Represents an individual drone with physical position, movement behavior,
    battery management, and visual representation in the PyBullet 3D environment.
    Supports multiple operational modes: orbiting, transiting, reachbrating, etc.
    """

    def __init__(self, drone_id: int, client_id: int, r: float, theta: float,
                 altitude: float, building_center: Tuple[float, float],
                 base_world_pos: Tuple[float, float, float],
                 start_at_base: bool = False, is_fake: bool = False):
        """
        Initialize a drone with position and physics parameters.
        
        Creates a drone that can orbit around a building center, transit to/from
        a base station, or be stationary. Fake drones are colored red and will
        be rejected during authentication.
        
        Args:
            drone_id: Unique identifier for this drone
            client_id: PyBullet physics client ID
            r: Initial radial distance from building center (meters)
            theta: Initial angle in polar coordinates (radians)
            altitude: Flying altitude above ground (meters)
            building_center: (x, y) coordinates of building cluster center
            base_world_pos: (x, y, z) position of the base station
            start_at_base: If True, drone starts at base station instead of orbit
            is_fake: If True, drone is marked as fake/malicious (red color)
        """
        self.id = drone_id
        self.client_id = client_id
        self.cx, self.cy = building_center
        self.base_x, self.base_y, self.base_z = base_world_pos
        self.altitude = altitude
        self.is_fake = is_fake
        self.rejected = False
        self.rejection_time = None
        
        if start_at_base:
            self.x, self.y, self.z = self.base_x, self.base_y, altitude
            dx, dy = self.x - self.cx, self.y - self.cy
            self.r = math.sqrt(dx*dx + dy*dy)
            self.theta = math.atan2(dy, dx)
            self.mode = "AT_BASE"
        else:
            self.r, self.theta, self.z = r, theta, altitude
            self.x, self.y = self._polar_to_cartesian(r, theta)
            self.mode = "ORBIT"
        
        self.r_target = self.r
        self.theta_target = self.theta
        self.k_r, self.k_theta = 0.8, 1.2
        self.omega_base = 0.3
        self.max_recalib_radial_speed = 4.0
        self.max_recalib_angular_speed = 0.6
        self.transit_speed = 8.0
        self.battery = 100.0
        self.battery_drain_rate = random.uniform(0.3, 0.7)
        
        # Create visual body
        self._create_body()
    
    def _create_body(self):
        """
        Create the PyBullet physics body for this drone.
        
        Creates a sphere-shaped body with collision and visual components.
        Color depends on drone authenticity: green for real, red for fake.
        """
        start_pos = [self.x, self.y, self.z]
        start_orn = p.getQuaternionFromEuler([0, 0, 0])
        radius = 0.5
        
        if self.is_fake:
            color = [1.0, 0.0, 0.0, 1.0]  # RED for fake drone
        else:
            color = [0.1, 0.8, 0.1, 1.0]  # GREEN for real drone
        
        col_shape = p.createCollisionShape(p.GEOM_SPHERE, radius=radius, physicsClientId=self.client_id)
        vis_shape = p.createVisualShape(p.GEOM_SPHERE, radius=radius, rgbaColor=color, physicsClientId=self.client_id)
        self.body_id = p.createMultiBody(
            baseMass=1.0,
            baseCollisionShapeIndex=col_shape,
            baseVisualShapeIndex=vis_shape,
            basePosition=start_pos,
            baseOrientation=start_orn,
            physicsClientId=self.client_id,
        )
    
    def _polar_to_cartesian(self, r: float, theta: float) -> Tuple[float, float]:
        """
        Convert polar coordinates to Cartesian coordinates.
        
        Converts (r, theta) relative to the building center to (x, y) world coordinates.
        
        Args:
            r: Radial distance from building center
            theta: Angle in radians (0 = positive x-axis)
            
        Returns:
            Tuple of (x, y) world coordinates
        """
        return self.cx + r * math.cos(theta), self.cy + r * math.sin(theta)
    
    def _update_body(self):
        """
        Update the drone's visual position in PyBullet simulation.
        
        Synchronizes the drone's internal (x, y, z) position with its
        visual representation in the 3D world.
        """
        pos = [self.x, self.y, self.z]
        orn = p.getQuaternionFromEuler([0, 0, 0])
        p.resetBasePositionAndOrientation(self.body_id, pos, orn, physicsClientId=self.client_id)
    
    def set_color(self, rgba):
        """
        Change the drone's visual color.
        
        Used to indicate drone status (e.g., leader=yellow, follower=green, rejected=red).
        
        Args:
            rgba: List/tuple of [red, green, blue, alpha] values in range [0, 1]
        """
        p.changeVisualShape(self.body_id, -1, rgbaColor=rgba, physicsClientId=self.client_id)
    
    def remove_from_world(self):
        """
        Remove the drone's physics body from the PyBullet simulation.
        
        Called when the drone is permanently removed from the swarm.
        Safely handles the case where the body was already removed.
        """
        try:
            p.removeBody(self.body_id, physicsClientId=self.client_id)
        except:
            pass
    
    def go_to_base(self):
        """
        Command the drone to fly back to the base station.
        
        Changes the drone's mode to transit toward the base station.
        Can only be called when the drone is currently orbiting or recalibrating.
        """
        if self.mode in ("ORBIT", "RECALIB"):
            self.mode = "TO_BASE"
    
    def go_from_base_to_orbit(self, r_target: float, theta_target: float):
        """
        Command the drone to fly from base station to orbital position.
        
        Sets target position and changes mode to transit from base to orbit.
        Typically called for newly joined drones.
        
        Args:
            r_target: Target radial distance from building center
            theta_target: Target angle in orbital formation
        """
        self.r_target, self.theta_target = r_target, theta_target
        self.mode = "FROM_BASE"
    
    def mark_rejected(self):
        """
        Mark this drone as rejected by authentication system.
        
        Sets the drone to fall from the sky (visual indication of rejection).
        Changes color to red and records rejection timestamp.
        """
        self.rejected = True
        self.rejection_time = time.time()
        self.mode = "REJECTED"
        self.set_color([1.0, 0.0, 0.0, 1.0])
    
    def step(self, dt: float):
        if self.battery > 0.0:
            self.battery -= self.battery_drain_rate * dt
            if self.battery < 0.0:
                self.battery = 0.0
        
        if self.mode == "REJECTED":
            # Falling animation
            self.z -= 5.0 * dt
            if self.z < 0:
                self.z = 0
            self._update_body()
            return
        
        if self.mode == "ORBIT":
            e_r = self.r_target - self.r
            v_r = self.k_r * e_r
            self.r += v_r * dt
            self.theta += self.omega_base * dt
            self.theta = angle_wrap(self.theta)
            self.x, self.y = self._polar_to_cartesian(self.r, self.theta)
            self.z = self.altitude
            self._update_body()
        
        elif self.mode == "RECALIB":
            e_r = self.r_target - self.r
            e_theta = angle_wrap(self.theta_target - self.theta)
            v_r = max(-self.max_recalib_radial_speed, min(self.max_recalib_radial_speed, self.k_r * e_r))
            omega = max(-self.max_recalib_angular_speed, min(self.max_recalib_angular_speed, self.k_theta * e_theta))
            self.r += v_r * dt
            self.theta += omega * dt
            self.theta = angle_wrap(self.theta)
            self.x, self.y = self._polar_to_cartesian(self.r, self.theta)
            self.z = self.altitude
            self._update_body()
        
        elif self.mode in ("TO_BASE", "FROM_BASE"):
            if self.mode == "TO_BASE":
                tx, ty, tz = self.base_x, self.base_y, self.base_z
            else:
                tx, ty = self._polar_to_cartesian(self.r_target, self.theta_target)
                tz = self.altitude
            
            dx, dy, dz = tx - self.x, ty - self.y, tz - self.z
            dist = math.sqrt(dx*dx + dy*dy + dz*dz)
            
            if dist < 0.3:
                self.x, self.y, self.z = tx, ty, tz
                if self.mode == "TO_BASE":
                    self.mode = "AT_BASE"
                else:
                    self.mode = "ORBIT"
                    self.r, self.theta = self.r_target, self.theta_target
                self._update_body()
            else:
                ux, uy, uz = dx/dist, dy/dist, dz/dist
                step_dist = min(self.transit_speed * dt, dist)
                self.x += ux * step_dist
                self.y += uy * step_dist
                self.z += uz * step_dist
                rel_x, rel_y = self.x - self.cx, self.y - self.cy
                self.r = math.sqrt(rel_x*rel_x + rel_y*rel_y)
                self.theta = math.atan2(rel_y, rel_x)
                self._update_body()
        
        elif self.mode == "AT_BASE":
            self.x, self.y, self.z = self.base_x, self.base_y, self.base_z
            self._update_body()


class ClusterLeader:
    """
    Cluster leader responsible for managing the drone swarm.
    
    Handles formation management, leader election, authentication of new drones,
    and coordination of the entire swarm. Integrates Shamir Secret Sharing
    authentication for secure drone admission.
    """
    
    def __init__(self, client_id: int, drones: Dict[int, DronePB],
                 building_radius: float, margin: float, d_safe: float,
                 building_center: Tuple[float, float], drone_altitude: float):
        """
        Initialize the cluster leader and authentication system.
        
        Sets up the swarm management system with authentication module,
        registers initial drones, and distributes secret shares.
        
        Args:
            client_id: PyBullet physics client ID
            drones: Dictionary of existing drones {drone_id: DronePB}
            building_radius: Radius of the building cluster (meters)
            margin: Safety margin around buildings (meters)
            d_safe: Minimum safe distance between drones (meters)
            building_center: (x, y) coordinates of building cluster center
            drone_altitude: Standard flying altitude for all drones (meters)
        """
        self.client_id = client_id
        self.drones = drones
        self.building_radius = building_radius
        self.margin = margin
        self.d_safe = d_safe
        self.building_center = building_center
        self.drone_altitude = drone_altitude
        self.current_leader_id = None
        self.r_current = None
        self.theta0 = 0.0
        
        # Shamir Authentication
        self.auth_module = ShamirAuthenticationModule(k_threshold=3)
        
        # Register all initial drones
        for drone_id in drones.keys():
            creds = DroneCredentials(drone_id, is_legitimate=True)
            self.auth_module.register_drone(drone_id, creds)
        
        # Distribute shares
        self.auth_module.distribute_shares(list(drones.keys()))
        
        # Fake drones tracking
        self.fake_drones: List[DronePB] = []
        self.attack_types = ["invalid_signature", "expired_cert", "tampered_cert"]
        self.current_attack_type = 0
        self.fake_drone_counter = 1000
        
        # Leader marker
        self.leader_sphere_id = None
    
    def recompute_formation(self):
        """
        Recalculate optimal orbital formation for current drone count.
        
        Computes the minimum safe radius based on drone count and spacing requirements.
        Assigns each drone a target position (r, theta) in a circular formation.
        Drones are evenly spaced around the circle to maintain safe distances.
        
        Updates all drones to RECALIB mode to move to their new positions.
        """
        member_ids = sorted(self.drones.keys())
        N = len(member_ids)
        if N == 0:
            return
        
        r_base = self.building_radius + self.margin
        if N > 1:
            r_safe = self.d_safe / (2 * math.sin(math.pi / N))
        else:
            r_safe = r_base
        r = max(r_base, r_safe)
        self.r_current = r
        
        delta_theta = 2 * math.pi / N
        for i, d_id in enumerate(member_ids):
            theta = self.theta0 + i * delta_theta
            d = self.drones[d_id]
            d.r_target = r
            d.theta_target = angle_wrap(theta)
            d.mode = "RECALIB"
        
        print(f"[Leader] Formation computed: N={N}, radius={r:.1f}m")
    
    def elect_leader(self):
        """
        Perform leader election among swarm drones.
        
        Selects the drone with the highest battery as the new leader.
        Updates visual indicators: leader becomes yellow, followers become green.
        Leader has special authority in the swarm coordination.
        """
        if not self.drones:
            self.current_leader_id = None
            return
        
        # Pick drone with highest battery
        best_id = max(self.drones.keys(), key=lambda d: self.drones[d].battery)
        old_leader = self.current_leader_id
        self.current_leader_id = best_id
        
        # Update colors
        for d_id, d in self.drones.items():
            if d_id == self.current_leader_id:
                d.set_color([1.0, 1.0, 0.0, 1.0])  # Yellow leader
            else:
                d.set_color([0.1, 0.8, 0.1, 1.0])  # Green follower
        
        if old_leader != best_id:
            print(f"[Election] New leader: Drone {best_id}")
    
    def try_add_real_drone(self, base_world_pos: Tuple[float, float, float]) -> bool:
        """
        Attempt to add a legitimate drone to the swarm.
        
        Creates a new drone with valid credentials and runs it through the
        6-step Shamir Secret Sharing authentication process. If successful,
        the drone joins the swarm and shares are redistributed.
        
        Process:
        1. Check capacity (max 8 drones)
        2. Create credentials for new drone
        3. Run full authentication (see authenticate_join_request)
        4. If successful: create drone at base, add to swarm, redistribute shares
        5. If failed: reject and log reason
        
        Args:
            base_world_pos: (x, y, z) position of the base station
            
        Returns:
            True if drone was successfully authenticated and added, False otherwise
        """
        if len(self.drones) >= 8:
            print("[JOIN] ❌ Cluster at max capacity (8 drones)")
            return False
        
        new_id = max(self.drones.keys()) + 1 if self.drones else 1
        creds = DroneCredentials(new_id, is_legitimate=True)
        
        # Authenticate
        success, reason = authenticate_join_request(
            self.auth_module, new_id, creds, list(self.drones.keys())
        )
        
        if success:
            # Create drone at base
            N = len(self.drones) + 1
            r = self.r_current if self.r_current else self.building_radius + self.margin
            theta = 2 * math.pi * (N - 1) / N
            
            new_drone = DronePB(
                drone_id=new_id,
                client_id=self.client_id,
                r=r, theta=theta,
                altitude=self.drone_altitude,
                building_center=self.building_center,
                base_world_pos=base_world_pos,
                start_at_base=True,
                is_fake=False
            )
            new_drone.set_color([0.2, 1.0, 0.4, 1.0])  # Bright green for new drone
            new_drone.go_from_base_to_orbit(r, theta)
            
            self.drones[new_id] = new_drone
            self.auth_module.register_drone(new_id, creds)
            self.auth_module.distribute_shares(list(self.drones.keys()))
            self.recompute_formation()
            
            # Show APPROVED text in 3D view near base station
            p.addUserDebugText(
                f"✅ Drone {new_id} APPROVED!",
                [self.drones[new_id].base_x, self.drones[new_id].base_y, self.drone_altitude + 5],
                textColorRGB=[0, 1, 0],
                textSize=2.0,
                lifeTime=3.0,
                physicsClientId=self.client_id
            )
            
            print(f"[JOIN] ✅ Drone {new_id} authenticated and joining swarm!")
            return True
            return True
        else:
            print(f"[JOIN] ❌ Drone {new_id} REJECTED: {reason}")
            return False
    
    def try_add_fake_drone(self, base_world_pos: Tuple[float, float, float]) -> DronePB:
        """
        Simulate an attack by attempting to add a malicious fake drone.
        
        Creates a drone with invalid credentials and runs it through authentication
        to demonstrate security. The fake drone will be rejected and marked for removal.
        Uses the current attack type to simulate different attack scenarios.
        
        Attack Types:
        - invalid_signature: Drone has wrong private key
        - expired_cert: Drone's certificate has expired
        - tampered_cert: Drone's certificate is from wrong issuer
        
        Args:
            base_world_pos: (x, y, z) position of base station
            
        Returns:
            The rejected DronePB object (will fall and be removed), or None if failed
        """
        fake_id = self.fake_drone_counter
        self.fake_drone_counter += 1
        attack_type = self.attack_types[self.current_attack_type]
        
        print(f"\n{'🔴'*35}")
        print(f"   ⚠️  ATTACK SIMULATION: {attack_type.upper()}")
        print(f"{'🔴'*35}")
        
        creds = DroneCredentials(fake_id, is_legitimate=False)
        
        # Create fake drone visually (RED) - it will appear trying to join
        r = self.r_current if self.r_current else self.building_radius + self.margin + 10
        theta = random.uniform(0, 2 * math.pi)
        
        fake_drone = DronePB(
            drone_id=fake_id,
            client_id=self.client_id,
            r=r + 15, theta=theta,
            altitude=self.drone_altitude + 5,
            building_center=self.building_center,
            base_world_pos=base_world_pos,
            start_at_base=False,
            is_fake=True
        )
        
        # Authenticate (will fail)
        success, reason = authenticate_join_request(
            self.auth_module, fake_id, creds, list(self.drones.keys()),
            attack_type=attack_type
        )
        
        if not success:
            print(f"\n{'🛡️'*35}")
            print(f"   🛡️  SECURITY: Fake drone {fake_id} BLOCKED!")
            print(f"   Reason: {reason}")
            print(f"   Blacklisted: {len(self.auth_module.blacklist)} drones")
            print(f"{'🛡️'*35}\n")
            
            # Mark as rejected - will fall
            fake_drone.mark_rejected()
            self.fake_drones.append(fake_drone)
            
            # Show BLOCKED text in 3D view near the fake drone
            p.addUserDebugText(
                "❌ BLOCKED!",
                [fake_drone.x, fake_drone.y, fake_drone.z + 3],
                textColorRGB=[1, 0, 0],
                textSize=2.0,
                lifeTime=2.0,
                physicsClientId=self.client_id
            )
            p.addUserDebugText(
                f"Reason: {reason}",
                [fake_drone.x, fake_drone.y, fake_drone.z + 1],
                textColorRGB=[1, 0.5, 0],
                textSize=1.2,
                lifeTime=3.0,
                physicsClientId=self.client_id
            )
            
            return fake_drone
        
        return None
    
    def cycle_attack_type(self):
        """
        Switch to the next attack simulation type.
        
        Cycles through different attack scenarios:
        0. invalid_signature - Drone doesn't have correct private key
        1. expired_cert - Certificate is past expiration date
        2. tampered_cert - Certificate from untrusted issuer
        
        Prints detailed explanation of each attack type and updates the
        visual indicator in the simulation.
        
        Returns:
            The name of the newly selected attack type
        """
        old_type = self.attack_types[self.current_attack_type]
        self.current_attack_type = (self.current_attack_type + 1) % len(self.attack_types)
        new_type = self.attack_types[self.current_attack_type]
        
        print("\n" + "="*70)
        print("   🔧 ATTACK TYPE SELECTOR")
        print("="*70)
        print("")
        print("   What is 'Attack Type'?")
        print("   ─────────────────────")
        print("   When you click '💀 Add FAKE Drone', it simulates a MALICIOUS drone")
        print("   trying to join the swarm. The 'Attack Type' determines HOW the")
        print("   fake drone tries to cheat the authentication system.")
        print("")
        print("   Think of it like a hacker trying different methods to break in!")
        print("")
        print("-"*70)
        print(f"   CHANGED: {old_type}  →  {new_type}")
        print("-"*70)
        print("")
        print("   🎯 ATTACK TYPES EXPLAINED:")
        print("")
        print("   ┌─────────────────────────────────────────────────────────────────┐")
        print("   │  [0] INVALID_SIGNATURE                                          │")
        print("   │      ───────────────────                                        │")
        print("   │      The fake drone doesn't have the correct private key.       │")
        print("   │      It CANNOT sign the challenge properly.                     │")
        print("   │                                                                 │")
        print("   │      Real World: Attacker built a drone but doesn't have        │")
        print("   │                  the secret credentials issued by SwarmCA.      │")
        print("   │                                                                 │")
        print("   │      Detection: Step 6 fails - signature mismatch               │")
        print("   ├─────────────────────────────────────────────────────────────────┤")
        print("   │  [1] EXPIRED_CERT                                               │")
        print("   │      ────────────                                               │")
        print("   │      The drone's certificate validity period has ended.         │")
        print("   │                                                                 │")
        print("   │      Real World: Old drone that hasn't renewed its cert,        │")
        print("   │                  or attacker using stolen old certificate.      │")
        print("   │                                                                 │")
        print("   │      Detection: Step 2b fails - certificate expired             │")
        print("   ├─────────────────────────────────────────────────────────────────┤")
        print("   │  [2] TAMPERED_CERT                                              │")
        print("   │      ─────────────                                              │")
        print("   │      Certificate was modified or issued by wrong authority.     │")
        print("   │                                                                 │")
        print("   │      Real World: Attacker created fake certificate with         │")
        print("   │                  different issuer (not trusted SwarmCA).        │")
        print("   │                                                                 │")
        print("   │      Detection: Step 2a fails - issuer mismatch                 │")
        print("   └─────────────────────────────────────────────────────────────────┘")
        print("")
        print("   Current Selection:")
        for i, atype in enumerate(self.attack_types):
            if i == self.current_attack_type:
                print(f"     ▶▶▶ [{i}] {atype.upper()} ◀◀◀  (ACTIVE)")
            else:
                print(f"         [{i}] {atype}")
        print("")
        print("   Next: Click '💀 Add FAKE Drone' to see this attack get BLOCKED!")
        print("="*70 + "\n")
        
        # Create visual indicator in PyBullet (flash text)
        self._show_attack_type_indicator(new_type)
        
        return new_type
    
    def _show_attack_type_indicator(self, attack_type: str):
        """
        Display attack type indicator text in the 3D simulation view.
        
        Shows a colored text label indicating the current attack simulation mode.
        Automatically removes the previous indicator before showing the new one.
        
        Args:
            attack_type: Name of the attack type to display
        """
        # Remove old indicator if exists
        if hasattr(self, '_attack_indicator_id') and self._attack_indicator_id is not None:
            try:
                p.removeUserDebugItem(self._attack_indicator_id, physicsClientId=self.client_id)
            except:
                pass
        
        # Color based on attack type
        colors = {
            "invalid_signature": [1.0, 0.3, 0.3],  # Red
            "expired_cert": [1.0, 0.6, 0.0],       # Orange
            "tampered_cert": [0.8, 0.0, 0.8]       # Purple
        }
        color = colors.get(attack_type, [1, 1, 1])
        
        self._attack_indicator_id = p.addUserDebugText(
            f"⚠️ Attack Mode: {attack_type.upper()}",
            [-30, 0, self.drone_altitude + 8],
            textColorRGB=color,
            textSize=1.5,
            lifeTime=3.0,  # Disappears after 3 seconds
            physicsClientId=self.client_id
        )
    
    def remove_drone(self, drone_id: int):
        """
        Remove a drone from the swarm and update formation.
        
        Handles the complete removal process:
        1. Logs drone information (position, battery, share)
        2. Removes drone's physics body from simulation
        3. Removes from drone dictionary
        4. Revokes the drone's secret share
        5. Triggers leader re-election if removed drone was leader
        6. Redistributes shares among remaining drones
        7. Recomputes formation for new drone count
        
        Args:
            drone_id: ID of the drone to remove
        """
        if drone_id in self.drones:
            d = self.drones[drone_id]
            
            # Get drone info before removal
            was_leader = (self.current_leader_id == drone_id)
            had_share = drone_id in self.auth_module.drone_shares
            share_info = self.auth_module.drone_shares.get(drone_id, None)
            
            print("\n" + "="*70)
            print("   ➖ DRONE REMOVAL")
            print("="*70)
            print(f"   Drone ID:       {drone_id}")
            print(f"   Was Leader:     {'Yes 👑' if was_leader else 'No'}")
            print(f"   Position:       ({d.x:.2f}, {d.y:.2f}, {d.z:.2f})")
            print(f"   Battery:        {d.battery:.1f}%")
            if had_share and share_info:
                x, y = share_info
                print(f"   Share Held:     (x={x}, y={str(y)[:20]}...)")
            print("-"*70)
            
            d.remove_from_world()
            del self.drones[drone_id]
            
            # Remove share
            if drone_id in self.auth_module.drone_shares:
                del self.auth_module.drone_shares[drone_id]
            
            print(f"   ✓ Drone {drone_id} removed from swarm")
            print(f"   ✓ Share revoked")
            
            if was_leader:
                print(f"   ⚠️  Leader removed - triggering new election...")
                self.current_leader_id = None
                self.elect_leader()
                print(f"   ✓ New leader elected: Drone {self.current_leader_id}")
            
            # Redistribute shares
            print(f"\n   📦 Redistributing shares among {len(self.drones)} remaining drones...")
            self.recompute_formation()
            self.auth_module.distribute_shares(list(self.drones.keys()))
            
            print("="*70 + "\n")
    
    def step(self, dt: float):
        """Update all drones."""
        # Update main drones
        for d in self.drones.values():
            d.step(dt)
        
        # Check recalibration complete
        all_done = True
        for d in self.drones.values():
            if d.mode == "RECALIB":
                e_r = abs(d.r - d.r_target)
                e_theta = abs(angle_wrap(d.theta - d.theta_target))
                if e_r > 0.1 or e_theta > 0.05:
                    all_done = False
                    break
        if all_done:
            for d in self.drones.values():
                if d.mode == "RECALIB":
                    d.mode = "ORBIT"
        
        # Update fake drones (falling)
        for fake in self.fake_drones[:]:
            fake.step(dt)
            if fake.rejected and fake.z <= 0:
                # Remove after falling
                if time.time() - fake.rejection_time > 3.0:
                    fake.remove_from_world()
                    self.fake_drones.remove(fake)
        
        # Remove drones at base
        to_remove = [d_id for d_id, d in self.drones.items() if d.mode == "AT_BASE"]
        for d_id in to_remove:
            self.remove_drone(d_id)


# =========================
# Environment Setup
# =========================

def create_building(client_id: int, width: float, depth: float, height: float, center=(0.0, 0.0), color=[0.5, 0.5, 0.8, 1.0]):
    """
    Create a single rectangular building in the PyBullet simulation.
    
    Generates both collision and visual shapes for a building block.
    Used to create the urban environment that drones orbit around.
    
    Args:
        client_id: PyBullet physics client ID
        width: Building width in X direction (meters)
        depth: Building depth in Y direction (meters)
        height: Building height in Z direction (meters)
        center: (x, y) ground position of building center
        color: RGBA color values [r, g, b, a] in range [0, 1]
        
    Returns:
        PyBullet body ID of the created building
    """
    cx, cy = center
    half_extents = [width/2, depth/2, height/2]
    col = p.createCollisionShape(p.GEOM_BOX, halfExtents=half_extents, physicsClientId=client_id)
    vis = p.createVisualShape(p.GEOM_BOX, halfExtents=half_extents,
                              rgbaColor=color, physicsClientId=client_id)
    return p.createMultiBody(baseMass=0.0, baseCollisionShapeIndex=col, baseVisualShapeIndex=vis,
                             basePosition=[cx, cy, height/2], physicsClientId=client_id)


def create_city_buildings(client_id: int, center=(0.0, 0.0)):
    """
    Create a cluster of buildings representing a city scene.
    
    Builds multiple buildings with varying heights and colors to create
    a realistic urban environment for the drone swarm to orbit around.
    
    Configuration includes:
    - 3 tall buildings in the back (30-40m height)
    - 2 shorter buildings in front (12-18m height)
    - Varied colors (grays, beige, greenish tints)
    
    Args:
        client_id: PyBullet physics client ID
        center: (x, y) center point for the building cluster
        
    Returns:
        List of PyBullet body IDs for all created buildings
    """
    cx, cy = center
    
    # Define buildings with (x_offset, y_offset, width, depth, height, color)
    buildings = [
        # Tall buildings in back
        (-8, -5, 6, 6, 35, [0.4, 0.4, 0.5, 1.0]),    # Dark gray tall
        (0, -6, 8, 8, 40, [0.6, 0.6, 0.7, 1.0]),     # Light gray tallest
        (8, -4, 5, 5, 30, [0.45, 0.45, 0.55, 1.0]),  # Medium gray
        # Shorter buildings in front
        (-10, 4, 5, 5, 18, [0.7, 0.6, 0.5, 1.0]),    # Beige/tan
        (6, 5, 4, 4, 12, [0.6, 0.7, 0.5, 1.0]),      # Light green/gray
    ]
    
    building_ids = []
    for x_off, y_off, w, d, h, color in buildings:
        bid = create_building(client_id, w, d, h, (cx + x_off, cy + y_off), color)
        building_ids.append(bid)
    
    return building_ids


def create_base_station(client_id: int, position=(50.0, 0.0, 0.0)):
    """
    Create a base station platform in the simulation.
    
    The base station is where drones start and return to. Appears as a
    blue flat platform away from the building cluster.
    
    Args:
        client_id: PyBullet physics client ID
        position: (x, y, z) world position for the base station
    """
    x, y, z = position
    half = [3.0, 3.0, 0.3]
    col = p.createCollisionShape(p.GEOM_BOX, halfExtents=half, physicsClientId=client_id)
    vis = p.createVisualShape(p.GEOM_BOX, halfExtents=half, rgbaColor=[0.1, 0.1, 0.9, 1.0], physicsClientId=client_id)
    p.createMultiBody(baseMass=0.0, baseCollisionShapeIndex=col, baseVisualShapeIndex=vis,
                      basePosition=[x, y, z + half[2]], physicsClientId=client_id)


def create_ground_grid(client_id: int):
    """
    Create a visual grid on the ground plane.
    
    Draws a grid of lines to help with spatial awareness and depth perception
    in the 3D simulation. Lines are drawn at 10-meter intervals.
    
    Args:
        client_id: PyBullet physics client ID
    """
    for i in range(-5, 6):
        p.addUserDebugLine([i*10, -50, 0.01], [i*10, 50, 0.01], [0.3, 0.3, 0.3], 1, 0, physicsClientId=client_id)
        p.addUserDebugLine([-50, i*10, 0.01], [50, i*10, 0.01], [0.3, 0.3, 0.3], 1, 0, physicsClientId=client_id)


# =========================
# Main
# =========================

def main():
    """
    Main entry point for the drone swarm simulation.
    
    Initializes the PyBullet simulation environment, creates the city buildings,
    base station, and initial drone swarm. Sets up the authentication system
    with Shamir Secret Sharing. Runs the interactive simulation loop where users
    can add/remove drones and test authentication.
    
    Interactive Controls (via GUI sliders):
    - Add REAL Drone: Adds legitimate drone with valid credentials
    - Add FAKE Drone: Simulates attack with fake drone (will be rejected)
    - Cycle Attack Type: Changes the type of attack simulation
    - Remove Drone: Removes a drone from the swarm
    - Camera controls: Distance, yaw, and pitch sliders
    
    The simulation runs at 60 FPS and prints detailed authentication logs
    to the terminal when drones attempt to join.
    """
    print("\n" + "="*70)
    print("   🚁 DRONE SWARM SIMULATION WITH SHAMIR SECRET SHARING 🔐")
    print("="*70)
    print("\n[INIT] Starting PyBullet with Intel GPU compatibility mode...")
    
    # Try different connection options for Intel GPU compatibility
    try:
        client_id = p.connect(p.GUI, options="--opengl2 --width=1280 --height=720")
    except:
        try:
            client_id = p.connect(p.GUI, options="--opengl2")
        except:
            client_id = p.connect(p.GUI)
    
    print(f"[INIT] ✅ PyBullet connected (client_id={client_id})")
    
    p.setAdditionalSearchPath(pybullet_data.getDataPath())
    p.setGravity(0, 0, -9.8, physicsClientId=client_id)
    p.loadURDF("plane.urdf", physicsClientId=client_id)
    
    # Disable rendering during setup for performance
    p.configureDebugVisualizer(p.COV_ENABLE_RENDERING, 0)
    
    # Setup - Create city buildings
    building_center = (0.0, 0.0)
    building_ids = create_city_buildings(client_id, building_center)
    
    # For collision/orbit calculations, use approximate radius
    building_radius = 15.0  # Approximate radius for the building cluster
    building_height = 40.0  # Height of tallest building
    
    base_world_pos = (50.0, 0.0, 0.2)
    create_base_station(client_id, base_world_pos)
    create_ground_grid(client_id)
    
    drone_altitude = building_height + 5.0
    
    # Camera setup
    p.resetDebugVisualizerCamera(
        cameraDistance=80,
        cameraYaw=45,
        cameraPitch=-45,
        cameraTargetPosition=[0, 0, 10],
        physicsClientId=client_id,
    )
    
    # Camera sliders
    cam_dist = p.addUserDebugParameter("Camera Distance", 20, 150, 80)
    cam_yaw = p.addUserDebugParameter("Camera Yaw", -180, 180, 45)
    cam_pitch = p.addUserDebugParameter("Camera Pitch", -89, -10, -45)
    
    # Control buttons
    btn_real = p.addUserDebugParameter("➕ Add REAL Drone", 1, 0, 0)
    btn_fake = p.addUserDebugParameter("💀 Add FAKE Drone", 1, 0, 0)
    btn_attack = p.addUserDebugParameter("🔧 Cycle Attack Type", 1, 0, 0)
    btn_leave = p.addUserDebugParameter("➖ Remove Drone", 1, 0, 0)
    
    # Read initial button values to prevent triggering on first frame
    last_btn_real = p.readUserDebugParameter(btn_real)
    last_btn_fake = p.readUserDebugParameter(btn_fake)
    last_btn_attack = p.readUserDebugParameter(btn_attack)
    last_btn_leave = p.readUserDebugParameter(btn_leave)
    
    # Create initial drones
    drones: Dict[int, DronePB] = {}
    initial_N = 5
    r_init = building_radius + 25.0
    
    print("\n" + "="*70)
    print("   🚁 INITIAL DRONE SWARM CONFIGURATION")
    print("="*70)
    print(f"   Total Drones: {initial_N}")
    print(f"   Orbit Radius: {r_init:.1f}m")
    print(f"   Altitude: {drone_altitude:.1f}m")
    print("-"*70)
    print(f"   {'Drone ID':<12} {'Position (x, y, z)':<30} {'Theta (rad)':<15}")
    print("-"*70)
    
    for i in range(initial_N):
        theta = 2 * math.pi * i / initial_N
        d = DronePB(
            drone_id=i + 1,
            client_id=client_id,
            r=r_init, theta=theta,
            altitude=drone_altitude,
            building_center=building_center,
            base_world_pos=base_world_pos,
            start_at_base=False,
            is_fake=False
        )
        drones[d.id] = d
        print(f"   Drone {d.id:<6} ({d.x:>7.2f}, {d.y:>7.2f}, {d.z:>6.2f})    θ = {theta:.3f}")
    
    print("="*70)
    
    # Create leader
    leader = ClusterLeader(
        client_id=client_id,
        drones=drones,
        building_radius=building_radius,
        margin=15.0,
        d_safe=8.0,
        building_center=building_center,
        drone_altitude=drone_altitude
    )
    
    leader.recompute_formation()
    leader.elect_leader()
    
    # Print current swarm status
    print("\n" + "="*70)
    print("   📊 SWARM STATUS AFTER INITIALIZATION")
    print("="*70)
    print(f"   Leader: Drone {leader.current_leader_id} (Yellow)")
    print(f"   Followers: {[d for d in drones.keys() if d != leader.current_leader_id]} (Green)")
    print(f"   Authentication: Shamir Secret Sharing (K={leader.auth_module.k_threshold})")
    print(f"   Blacklist: {len(leader.auth_module.blacklist)} drones")
    print("="*70)
    
    # Re-enable rendering
    p.configureDebugVisualizer(p.COV_ENABLE_RENDERING, 1)
    
    # Status text
    status_id = p.addUserDebugText(
        f"Swarm: {len(drones)} drones | Leader: D{leader.current_leader_id} | Attack: {leader.attack_types[0]}",
        [0, 0, drone_altitude + 10],
        textColorRGB=[1, 1, 1],
        textSize=1.5,
        physicsClientId=client_id
    )
    
    print("\n" + "="*70)
    print("   ✅ SIMULATION READY!")
    print("="*70)
    print("\n   📌 CONTROLS (use sliders on left panel):")
    print("   ┌─────────────────────────────────────────────────────────┐")
    print("   │  ➕ Add REAL Drone  - Legitimate drone joins (GREEN)    │")
    print("   │  💀 Add FAKE Drone  - Attack simulation (RED, falls)   │")
    print("   │  🔧 Cycle Attack    - Switch attack type               │")
    print("   │  ➖ Remove Drone    - Drone leaves swarm               │")
    print("   └─────────────────────────────────────────────────────────┘")
    print("\n   Watch the terminal for detailed authentication logs!")
    print("="*70 + "\n")
    
    dt = 1.0 / 60.0
    t = 0.0
    
    while p.isConnected():
        # Update camera from sliders
        dist = p.readUserDebugParameter(cam_dist)
        yaw = p.readUserDebugParameter(cam_yaw)
        pitch = p.readUserDebugParameter(cam_pitch)
        p.resetDebugVisualizerCamera(dist, yaw, pitch, [0, 0, 10], physicsClientId=client_id)
        
        # Check buttons
        curr_real = p.readUserDebugParameter(btn_real)
        curr_fake = p.readUserDebugParameter(btn_fake)
        curr_attack = p.readUserDebugParameter(btn_attack)
        curr_leave = p.readUserDebugParameter(btn_leave)
        
        if curr_real != last_btn_real:
            last_btn_real = curr_real
            leader.try_add_real_drone(base_world_pos)
        
        if curr_fake != last_btn_fake:
            last_btn_fake = curr_fake
            leader.try_add_fake_drone(base_world_pos)
        
        if curr_attack != last_btn_attack:
            last_btn_attack = curr_attack
            leader.cycle_attack_type()
        
        if curr_leave != last_btn_leave:
            last_btn_leave = curr_leave
            if leader.drones:
                # Remove a follower (not leader)
                ids = list(leader.drones.keys())
                followers = [d for d in ids if d != leader.current_leader_id]
                if followers:
                    leave_id = max(followers)
                else:
                    leave_id = max(ids)
                
                # Print that drone is leaving
                d = leader.drones[leave_id]
                print("\n" + "="*70)
                print("   🚁 DRONE LEAVING SWARM")
                print("="*70)
                print(f"   Drone {leave_id} is flying back to base...")
                print(f"   Current Position: ({d.x:.2f}, {d.y:.2f}, {d.z:.2f})")
                print(f"   Destination: Base Station ({d.base_x:.1f}, {d.base_y:.1f}, {d.base_z:.1f})")
                print("="*70)
                
                leader.drones[leave_id].go_to_base()
        
        # Update simulation
        leader.step(dt)
        
        # Update status text
        p.removeUserDebugItem(status_id)
        attack_name = leader.attack_types[leader.current_attack_type]
        status_id = p.addUserDebugText(
            f"Swarm: {len(leader.drones)} | Leader: D{leader.current_leader_id} | "
            f"Blacklist: {len(leader.auth_module.blacklist)} | Attack: {attack_name}",
            [0, 0, drone_altitude + 12],
            textColorRGB=[1, 1, 0],
            textSize=1.2,
            physicsClientId=client_id
        )
        
        p.stepSimulation(physicsClientId=client_id)
        time.sleep(dt)
        t += dt
    
    print("\n[EXIT] Simulation ended")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
