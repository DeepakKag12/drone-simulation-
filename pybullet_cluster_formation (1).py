"""
Drone Swarm Simulation with Shamir Secret Sharing Authentication
PyBullet 3D simulation — headless/Xvfb compatible for Render deployment
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

import pybullet as p
import pybullet_data


# =========================
# Shamir Secret Sharing
# =========================

class ShamirSecretSharing:
    PRIME = 2**127 - 1

    def __init__(self):
        self.weights: List[int] = []
        self.x_coords: List[int] = []

    @staticmethod
    def _mod_inverse(a: int, prime: int) -> int:
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            return gcd, y1 - (b // a) * x1, x1
        _, x, _ = extended_gcd(a % prime, prime)
        return (x % prime + prime) % prime

    def precompute_weights(self, x_coords: List[int], prime: int) -> List[int]:
        k = len(x_coords)
        prefix = [1] * (k + 1)
        for i in range(k):
            prefix[i+1] = (prefix[i] * (-x_coords[i])) % prime
        suffix = [1] * (k + 1)
        for i in range(k - 1, -1, -1):
            suffix[i] = (suffix[i+1] * (-x_coords[i])) % prime
        weights = []
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
    def reconstruct_secret_fast(shares, weights, prime):
        secret = 0
        for (xi, yi), wi in zip(shares, weights):
            secret = (secret + yi * wi) % prime
        return secret


# =========================
# PKI Credentials
# =========================

class DroneCredentials:
    def __init__(self, drone_id: int, is_legitimate: bool = True):
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
        return hashlib.sha256(f"{self.private_key}{message}".encode()).hexdigest()

    def verify_signature(self, message: str, signature: str) -> bool:
        expected = hashlib.sha256(f"{self.private_key}{message}".encode()).hexdigest()
        return secrets.compare_digest(signature, expected)


# =========================
# Authentication Module
# =========================

class ShamirAuthenticationModule:
    def __init__(self, k_threshold: int = 3):
        self.k_threshold = k_threshold
        self.master_secret = secrets.randbelow(ShamirSecretSharing.PRIME)
        self.drone_shares: Dict[int, Tuple[int, int]] = {}
        self.drone_credentials: Dict[int, DroneCredentials] = {}
        self.blacklist: set = set()
        self.sss_engine = ShamirSecretSharing()
        self.pending_challenges: Dict[int, str] = {}

    def register_drone(self, drone_id: int, credentials: DroneCredentials):
        self.drone_credentials[drone_id] = credentials

    def distribute_shares(self, drone_ids: List[int]):
        n = len(drone_ids)
        if n < self.k_threshold:
            print(f"[SHARES] ⚠️  Warning: Only {n} drones, need {self.k_threshold} for reconstruction")
            return
        shares = ShamirSecretSharing.generate_shares(self.master_secret, self.k_threshold, n)
        self.drone_shares.clear()
        for drone_id, share in zip(drone_ids, shares):
            self.drone_shares[drone_id] = share

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
        shares = [self.drone_shares[d] for d in selected_ids if d in self.drone_shares]
        if len(shares) < self.k_threshold:
            return None
        x_coords_used = [s[0] for s in shares[:self.k_threshold]]
        if self.sss_engine.x_coords != x_coords_used:
            self.sss_engine.precompute_weights(x_coords_used, ShamirSecretSharing.PRIME)
        return self.sss_engine.reconstruct_secret_fast(
            shares[:self.k_threshold], self.sss_engine.weights, ShamirSecretSharing.PRIME)

    def generate_challenge(self, drone_id: int, nonce: str, secret: int) -> str:
        challenge = hashlib.sha256(f"{secret}{drone_id}{nonce}".encode()).hexdigest()
        self.pending_challenges[drone_id] = challenge
        return challenge

    def verify_response(self, drone_id: int, response: str, creds: DroneCredentials) -> Tuple[bool, str]:
        if drone_id not in self.pending_challenges:
            return False, "No pending challenge"
        challenge = self.pending_challenges[drone_id]
        if not creds.verify_signature(challenge, response):
            return False, "Invalid signature"
        del self.pending_challenges[drone_id]
        return True, "Verified"

    def add_to_blacklist(self, drone_id: int, reason: str):
        self.blacklist.add(drone_id)
        print(f"[BLACKLIST] ⛔ Drone {drone_id}: {reason}")


# =========================
# Authentication Flow
# =========================

def authenticate_join_request(auth_module, joining_drone_id, credentials,
                               existing_drone_ids, attack_type=None):
    print("\n" + "="*70)
    print(f"   🔐 AUTHENTICATION: Drone {joining_drone_id} requesting to join")
    print("="*70)

    # Step 1: Blacklist
    if joining_drone_id in auth_module.blacklist:
        return False, "Drone is blacklisted"

    # Step 2: Certificate
    cert = credentials.certificate
    if attack_type == "tampered_cert":
        auth_module.add_to_blacklist(joining_drone_id, "Certificate tampered")
        return False, "Certificate tampered - issuer mismatch"
    if attack_type == "expired_cert":
        auth_module.add_to_blacklist(joining_drone_id, "Certificate expired")
        return False, "Certificate expired"
    if not cert.get("is_legitimate", True):
        auth_module.add_to_blacklist(joining_drone_id, "Invalid certificate")
        return False, "Invalid certificate - not legitimate"

    # Step 3: Select K trusted drones
    available = [d for d in existing_drone_ids if d in auth_module.drone_shares]
    if len(available) < auth_module.k_threshold:
        return False, f"Insufficient drones ({len(available)}/{auth_module.k_threshold})"
    selected = random.sample(available, auth_module.k_threshold)
    print(f"[STEP 3] Selected drones for reconstruction: {selected}")

    # Step 4: Reconstruct secret
    reconstructed = auth_module.reconstruct_secret(selected)
    if reconstructed is None:
        return False, "Failed to reconstruct secret"
    print(f"[STEP 4] Secret reconstructed successfully")

    # Step 5: Challenge
    nonce = secrets.token_hex(16)
    challenge = auth_module.generate_challenge(joining_drone_id, nonce, reconstructed)
    print(f"[STEP 5] Challenge generated: {challenge[:32]}...")

    # Step 6: Verify signature
    if attack_type == "invalid_signature":
        auth_module.add_to_blacklist(joining_drone_id, "Invalid signature")
        return False, "Invalid signature - drone cannot prove identity"

    signed = credentials.sign(challenge)
    success, msg = auth_module.verify_response(joining_drone_id, signed, credentials)
    if not success:
        auth_module.add_to_blacklist(joining_drone_id, msg)
        return False, msg

    print(f"[AUTH] ✅ Drone {joining_drone_id} authenticated successfully!")
    return True, "Authenticated successfully"


# =========================
# Helpers
# =========================

def angle_wrap(angle: float) -> float:
    return (angle + math.pi) % (2 * math.pi) - math.pi


# =========================
# Drone
# =========================

class DronePB:
    def __init__(self, drone_id, client_id, r, theta, altitude,
                 building_center, base_world_pos, start_at_base=False, is_fake=False):
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
        self._create_body()

    def _create_body(self):
        start_pos = [self.x, self.y, self.z]
        start_orn = p.getQuaternionFromEuler([0, 0, 0])
        radius = 0.5
        color = [1.0, 0.0, 0.0, 1.0] if self.is_fake else [0.1, 0.8, 0.1, 1.0]
        col = p.createCollisionShape(p.GEOM_SPHERE, radius=radius, physicsClientId=self.client_id)
        vis = p.createVisualShape(p.GEOM_SPHERE, radius=radius, rgbaColor=color, physicsClientId=self.client_id)
        self.body_id = p.createMultiBody(
            baseMass=1.0,
            baseCollisionShapeIndex=col,
            baseVisualShapeIndex=vis,
            basePosition=start_pos,
            baseOrientation=start_orn,
            physicsClientId=self.client_id,
        )

    def _polar_to_cartesian(self, r, theta):
        return self.cx + r * math.cos(theta), self.cy + r * math.sin(theta)

    def _update_body(self):
        p.resetBasePositionAndOrientation(
            self.body_id, [self.x, self.y, self.z],
            p.getQuaternionFromEuler([0, 0, 0]),
            physicsClientId=self.client_id)

    def set_color(self, rgba):
        p.changeVisualShape(self.body_id, -1, rgbaColor=rgba, physicsClientId=self.client_id)

    def remove_from_world(self):
        try:
            p.removeBody(self.body_id, physicsClientId=self.client_id)
        except:
            pass

    def go_to_base(self):
        if self.mode in ("ORBIT", "RECALIB"):
            self.mode = "TO_BASE"

    def go_from_base_to_orbit(self, r_target, theta_target):
        self.r_target, self.theta_target = r_target, theta_target
        self.mode = "FROM_BASE"

    def mark_rejected(self):
        self.rejected = True
        self.rejection_time = time.time()
        self.mode = "REJECTED"
        self.set_color([1.0, 0.0, 0.0, 1.0])

    def step(self, dt):
        if self.battery > 0.0:
            self.battery = max(0.0, self.battery - self.battery_drain_rate * dt)

        if self.mode == "REJECTED":
            self.z = max(0, self.z - 5.0 * dt)
            self._update_body()
            return

        if self.mode == "ORBIT":
            self.r += self.k_r * (self.r_target - self.r) * dt
            self.theta = angle_wrap(self.theta + self.omega_base * dt)
            self.x, self.y = self._polar_to_cartesian(self.r, self.theta)
            self.z = self.altitude
            self._update_body()

        elif self.mode == "RECALIB":
            e_r = self.r_target - self.r
            e_theta = angle_wrap(self.theta_target - self.theta)
            v_r = max(-self.max_recalib_radial_speed, min(self.max_recalib_radial_speed, self.k_r * e_r))
            omega = max(-self.max_recalib_angular_speed, min(self.max_recalib_angular_speed, self.k_theta * e_theta))
            self.r += v_r * dt
            self.theta = angle_wrap(self.theta + omega * dt)
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
            else:
                step = min(self.transit_speed * dt, dist)
                self.x += (dx/dist) * step
                self.y += (dy/dist) * step
                self.z += (dz/dist) * step
                rel_x, rel_y = self.x - self.cx, self.y - self.cy
                self.r = math.sqrt(rel_x*rel_x + rel_y*rel_y)
                self.theta = math.atan2(rel_y, rel_x)
            self._update_body()

        elif self.mode == "AT_BASE":
            self.x, self.y, self.z = self.base_x, self.base_y, self.base_z
            self._update_body()


# =========================
# Cluster Leader
# =========================

class ClusterLeader:
    def __init__(self, client_id, drones, building_radius, margin, d_safe,
                 building_center, drone_altitude):
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

        self.auth_module = ShamirAuthenticationModule(k_threshold=3)
        for drone_id in drones.keys():
            creds = DroneCredentials(drone_id, is_legitimate=True)
            self.auth_module.register_drone(drone_id, creds)
        self.auth_module.distribute_shares(list(drones.keys()))

        self.fake_drones: List[DronePB] = []
        self.attack_types = ["invalid_signature", "expired_cert", "tampered_cert"]
        self.current_attack_type = 0
        self.fake_drone_counter = 1000
        self._attack_indicator_id = None

    def recompute_formation(self):
        member_ids = sorted(self.drones.keys())
        N = len(member_ids)
        if N == 0:
            return
        r_base = self.building_radius + self.margin
        r_safe = self.d_safe / (2 * math.sin(math.pi / N)) if N > 1 else r_base
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
        if not self.drones:
            self.current_leader_id = None
            return
        best_id = max(self.drones.keys(), key=lambda d: self.drones[d].battery)
        self.current_leader_id = best_id
        for d_id, d in self.drones.items():
            d.set_color([1.0, 1.0, 0.0, 1.0] if d_id == best_id else [0.1, 0.8, 0.1, 1.0])
        print(f"[Election] New leader: Drone {best_id}")

    def try_add_real_drone(self, base_world_pos):
        if len(self.drones) >= 8:
            print("[JOIN] ❌ Cluster at max capacity (8 drones)")
            return False
        new_id = max(self.drones.keys()) + 1 if self.drones else 1
        creds = DroneCredentials(new_id, is_legitimate=True)
        success, reason = authenticate_join_request(
            self.auth_module, new_id, creds, list(self.drones.keys()))
        if success:
            N = len(self.drones) + 1
            r = self.r_current or (self.building_radius + self.margin)
            theta = 2 * math.pi * (N - 1) / N
            new_drone = DronePB(
                drone_id=new_id, client_id=self.client_id,
                r=r, theta=theta, altitude=self.drone_altitude,
                building_center=self.building_center,
                base_world_pos=base_world_pos,
                start_at_base=True, is_fake=False)
            new_drone.set_color([0.2, 1.0, 0.4, 1.0])
            new_drone.go_from_base_to_orbit(r, theta)
            self.drones[new_id] = new_drone
            self.auth_module.register_drone(new_id, creds)
            self.auth_module.distribute_shares(list(self.drones.keys()))
            self.recompute_formation()
            try:
                p.addUserDebugText(
                    f"APPROVED: Drone {new_id}",
                    [self.drones[new_id].base_x, self.drones[new_id].base_y, self.drone_altitude + 5],
                    textColorRGB=[0, 1, 0], textSize=2.0, lifeTime=3.0,
                    physicsClientId=self.client_id)
            except:
                pass
            print(f"[JOIN] ✅ Drone {new_id} joined the swarm!")
            return True
        else:
            print(f"[JOIN] ❌ Drone {new_id} REJECTED: {reason}")
            return False

    def try_add_fake_drone(self, base_world_pos):
        fake_id = self.fake_drone_counter
        self.fake_drone_counter += 1
        attack_type = self.attack_types[self.current_attack_type]
        print(f"\n{'='*70}")
        print(f"   ⚠️  ATTACK SIMULATION: {attack_type.upper()}")
        print(f"{'='*70}")
        creds = DroneCredentials(fake_id, is_legitimate=False)
        r = (self.r_current or (self.building_radius + self.margin)) + 15
        theta = random.uniform(0, 2 * math.pi)
        fake_drone = DronePB(
            drone_id=fake_id, client_id=self.client_id,
            r=r, theta=theta, altitude=self.drone_altitude + 5,
            building_center=self.building_center,
            base_world_pos=base_world_pos,
            start_at_base=False, is_fake=True)
        success, reason = authenticate_join_request(
            self.auth_module, fake_id, creds, list(self.drones.keys()),
            attack_type=attack_type)
        if not success:
            print(f"[SECURITY] 🛡️ Fake drone {fake_id} BLOCKED: {reason}")
            fake_drone.mark_rejected()
            self.fake_drones.append(fake_drone)
            try:
                p.addUserDebugText(
                    "BLOCKED!",
                    [fake_drone.x, fake_drone.y, fake_drone.z + 3],
                    textColorRGB=[1, 0, 0], textSize=2.0, lifeTime=2.0,
                    physicsClientId=self.client_id)
            except:
                pass
            return fake_drone
        return None

    def cycle_attack_type(self):
        self.current_attack_type = (self.current_attack_type + 1) % len(self.attack_types)
        new_type = self.attack_types[self.current_attack_type]
        print(f"[ATTACK] Switched to: {new_type.upper()}")
        return new_type

    def remove_drone(self, drone_id):
        if drone_id not in self.drones:
            return
        was_leader = (self.current_leader_id == drone_id)
        self.drones[drone_id].remove_from_world()
        del self.drones[drone_id]
        if drone_id in self.auth_module.drone_shares:
            del self.auth_module.drone_shares[drone_id]
        print(f"[REMOVE] Drone {drone_id} removed (was_leader={was_leader})")
        if was_leader:
            self.elect_leader()
        if self.drones:
            self.recompute_formation()
            self.auth_module.distribute_shares(list(self.drones.keys()))

    def step(self, dt):
        for d in self.drones.values():
            d.step(dt)

        # Switch RECALIB → ORBIT when close enough
        for d in self.drones.values():
            if d.mode == "RECALIB":
                if abs(d.r - d.r_target) < 0.1 and abs(angle_wrap(d.theta - d.theta_target)) < 0.05:
                    d.mode = "ORBIT"

        # Update falling fake drones
        for fake in self.fake_drones[:]:
            fake.step(dt)
            if fake.z <= 0 and time.time() - fake.rejection_time > 3.0:
                fake.remove_from_world()
                self.fake_drones.remove(fake)

        # Remove drones that returned to base
        for d_id in [d_id for d_id, d in self.drones.items() if d.mode == "AT_BASE"]:
            self.remove_drone(d_id)


# =========================
# Environment
# =========================

def create_building(client_id, width, depth, height, center=(0.0, 0.0), color=None):
    if color is None:
        color = [0.5, 0.5, 0.8, 1.0]
    cx, cy = center
    he = [width/2, depth/2, height/2]
    col = p.createCollisionShape(p.GEOM_BOX, halfExtents=he, physicsClientId=client_id)
    vis = p.createVisualShape(p.GEOM_BOX, halfExtents=he, rgbaColor=color, physicsClientId=client_id)
    return p.createMultiBody(baseMass=0, baseCollisionShapeIndex=col,
                             baseVisualShapeIndex=vis,
                             basePosition=[cx, cy, height/2],
                             physicsClientId=client_id)


def create_city_buildings(client_id, center=(0.0, 0.0)):
    cx, cy = center
    buildings = [
        (-8, -5, 6, 6, 35, [0.4, 0.4, 0.5, 1.0]),
        (0,  -6, 8, 8, 40, [0.6, 0.6, 0.7, 1.0]),
        (8,  -4, 5, 5, 30, [0.45, 0.45, 0.55, 1.0]),
        (-10, 4, 5, 5, 18, [0.7, 0.6, 0.5, 1.0]),
        (6,   5, 4, 4, 12, [0.6, 0.7, 0.5, 1.0]),
    ]
    return [create_building(client_id, w, d, h, (cx+xo, cy+yo), c)
            for xo, yo, w, d, h, c in buildings]


def create_base_station(client_id, position=(50.0, 0.0, 0.0)):
    x, y, z = position
    he = [3.0, 3.0, 0.3]
    col = p.createCollisionShape(p.GEOM_BOX, halfExtents=he, physicsClientId=client_id)
    vis = p.createVisualShape(p.GEOM_BOX, halfExtents=he, rgbaColor=[0.1, 0.1, 0.9, 1.0], physicsClientId=client_id)
    p.createMultiBody(baseMass=0, baseCollisionShapeIndex=col, baseVisualShapeIndex=vis,
                      basePosition=[x, y, z + he[2]], physicsClientId=client_id)


def create_ground_grid(client_id):
    for i in range(-5, 6):
        p.addUserDebugLine([i*10, -50, 0.01], [i*10, 50, 0.01], [0.3, 0.3, 0.3], 1, 0, physicsClientId=client_id)
        p.addUserDebugLine([-50, i*10, 0.01], [50, i*10, 0.01], [0.3, 0.3, 0.3], 1, 0, physicsClientId=client_id)


# =========================
# Main
# =========================

def main():
    print("\n" + "="*70)
    print("   🚁 DRONE SWARM SIMULATION WITH SHAMIR SECRET SHARING 🔐")
    print("="*70)
    print("\n[INIT] Starting PyBullet with Intel GPU compatibility mode...")

    try:
        client_id = p.connect(p.GUI, options="--opengl2 --width=1280 --height=720")
    except Exception:
        try:
            client_id = p.connect(p.GUI, options="--opengl2")
        except Exception:
            client_id = p.connect(p.GUI)

    print(f"[INIT] ✅ PyBullet connected (client_id={client_id})")

    p.setAdditionalSearchPath(pybullet_data.getDataPath())
    p.setGravity(0, 0, -9.8, physicsClientId=client_id)
    p.loadURDF("plane.urdf", physicsClientId=client_id)
    p.configureDebugVisualizer(p.COV_ENABLE_RENDERING, 0)

    building_center = (0.0, 0.0)
    building_radius = 15.0
    building_height = 40.0
    base_world_pos = (50.0, 0.0, 0.2)
    drone_altitude = building_height + 5.0

    create_city_buildings(client_id, building_center)
    create_base_station(client_id, base_world_pos)
    create_ground_grid(client_id)

    p.resetDebugVisualizerCamera(80, 45, -45, [0, 0, 10], physicsClientId=client_id)

    # Camera sliders
    cam_dist  = p.addUserDebugParameter("Camera Distance", 20, 150, 80)
    cam_yaw   = p.addUserDebugParameter("Camera Yaw", -180, 180, 45)
    cam_pitch = p.addUserDebugParameter("Camera Pitch", -89, -10, -45)

    # Control buttons
    btn_real   = p.addUserDebugParameter("+ Add REAL Drone", 1, 0, 0)
    btn_fake   = p.addUserDebugParameter("X Add FAKE Drone", 1, 0, 0)
    btn_attack = p.addUserDebugParameter("* Cycle Attack Type", 1, 0, 0)
    btn_leave  = p.addUserDebugParameter("- Remove Drone", 1, 0, 0)

    last_real   = p.readUserDebugParameter(btn_real)
    last_fake   = p.readUserDebugParameter(btn_fake)
    last_attack = p.readUserDebugParameter(btn_attack)
    last_leave  = p.readUserDebugParameter(btn_leave)

    # Initial drones
    drones: Dict[int, DronePB] = {}
    initial_N = 5
    r_init = building_radius + 25.0

    print("\n" + "="*70)
    print("   🚁 INITIAL DRONE SWARM CONFIGURATION")
    print("="*70)
    print(f"   Total Drones: {initial_N}")
    print(f"   Orbit Radius: {r_init:.1f}m  |  Altitude: {drone_altitude:.1f}m")
    print("-"*70)

    for i in range(initial_N):
        theta = 2 * math.pi * i / initial_N
        d = DronePB(drone_id=i+1, client_id=client_id,
                    r=r_init, theta=theta, altitude=drone_altitude,
                    building_center=building_center,
                    base_world_pos=base_world_pos,
                    start_at_base=False, is_fake=False)
        drones[d.id] = d
        print(f"   Drone {d.id}: ({d.x:>7.2f}, {d.y:>7.2f}, {d.z:>6.2f})  θ={theta:.3f}")

    print("="*70)

    leader = ClusterLeader(
        client_id=client_id, drones=drones,
        building_radius=building_radius, margin=15.0, d_safe=8.0,
        building_center=building_center, drone_altitude=drone_altitude)

    leader.recompute_formation()
    leader.elect_leader()

    print(f"\n[SWARM] Leader: Drone {leader.current_leader_id}")
    print(f"[SWARM] Followers: {[d for d in drones if d != leader.current_leader_id]}")

    p.configureDebugVisualizer(p.COV_ENABLE_RENDERING, 1)

    status_id = p.addUserDebugText(
        f"Drones:{len(drones)} | Leader:D{leader.current_leader_id} | Attack:{leader.attack_types[0]}",
        [0, 0, drone_altitude + 12],
        textColorRGB=[1, 1, 0], textSize=1.2, physicsClientId=client_id)

    print("\n[SIM] ✅ SIMULATION RUNNING — use the left panel sliders to interact!\n")

    dt = 1.0 / 60.0

    while p.isConnected(physicsClientId=client_id):
        # Camera
        dist  = p.readUserDebugParameter(cam_dist)
        yaw   = p.readUserDebugParameter(cam_yaw)
        pitch = p.readUserDebugParameter(cam_pitch)
        p.resetDebugVisualizerCamera(dist, yaw, pitch, [0, 0, 10], physicsClientId=client_id)

        # Buttons
        curr_real   = p.readUserDebugParameter(btn_real)
        curr_fake   = p.readUserDebugParameter(btn_fake)
        curr_attack = p.readUserDebugParameter(btn_attack)
        curr_leave  = p.readUserDebugParameter(btn_leave)

        if curr_real != last_real:
            last_real = curr_real
            leader.try_add_real_drone(base_world_pos)

        if curr_fake != last_fake:
            last_fake = curr_fake
            leader.try_add_fake_drone(base_world_pos)

        if curr_attack != last_attack:
            last_attack = curr_attack
            leader.cycle_attack_type()

        if curr_leave != last_leave:
            last_leave = curr_leave
            if leader.drones:
                followers = [d for d in leader.drones if d != leader.current_leader_id]
                remove_id = max(followers) if followers else max(leader.drones.keys())
                leader.drones[remove_id].go_to_base()

        leader.step(dt)

        # Refresh status
        try:
            p.removeUserDebugItem(status_id)
        except:
            pass
        attack_name = leader.attack_types[leader.current_attack_type]
        status_id = p.addUserDebugText(
            f"Drones:{len(leader.drones)} | Leader:D{leader.current_leader_id} | "
            f"Blacklist:{len(leader.auth_module.blacklist)} | Attack:{attack_name}",
            [0, 0, drone_altitude + 12],
            textColorRGB=[1, 1, 0], textSize=1.2, physicsClientId=client_id)

        p.stepSimulation(physicsClientId=client_id)
        time.sleep(dt)

    print("\n[EXIT] Simulation ended")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"\n[ERROR] {e}")
        traceback.print_exc()