"""
3D PyBullet Drone Swarm Simulation with Threshold UAV Authentication Protocol.

Features:
- Realistic 3D urban environment with Ground Base Station command tower.
- Autonomous UAV swarm orbiting in tactical formation.
- Hardware Root of Trust: Every UAV is equipped with its own SRAM PUF simulator.
- Threshold Secret Sharing (t, k) mutual authentication with state ratcheting.
- Decentralized Quorum Admission & Verifiable Secret Sharing (VSS).
- Periodic Re-verification & Dynamic UAV Admission.
- Real-time Attack Demonstrations:
  * Cloned / Fraudulent PUF Drone (Black/Red)
  * Replay Attack (M1 re-injection, quarantined)
  * MitM Message / MAC Tampering (quarantined)
  * Captured / Noise-Corrupted Drone (> k-t errors, quarantined)
  * Poisoned Quorum Share Injection (VSS detected & quarantined)
- Trusted UAVs render in Green, Malicious/Quarantined UAVs render in Black/Red.
- Interactive PyBullet GUI buttons, 3D laser telemetry beams, and headless test mode.
"""

import math
import os
import random
import secrets
import sys
import time
from typing import Dict, List, Optional, Tuple

if sys.platform.startswith("win"):
    os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
    os.environ["OMP_NUM_THREADS"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"
    try:
        if sys.stdout:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import pybullet as p
import pybullet_data

from crypto.finite_field import (
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    random_secret,
)
from crypto.puf import SRAMPUF
from crypto.shamir import VerifiableSecretSharing
from crypto.protocol import (
    BaseStation,
    UAV,
    AuthMessage1,
    AuthMessage2,
    AuthMessage3,
    ProtocolMode,
    SwarmPeerNode,
    DecentralizedQuorumCoordinator,
    QuorumAdmissionResult,
)


# ==============================================================================
# Environment: 3D City Buildings & Base Station Tower
# ==============================================================================

class BuildingComplex:
    """Creates a 3D urban environment with central Base Station tower."""

    def __init__(self, client_id: int, center: Tuple[float, float] = (0.0, 0.0)):
        self.client_id = client_id
        self.center = center
        self.buildings: List[int] = []
        self.max_height = 35.0
        self._build_city()

    def _build_city(self):
        configs = [
            # (rel_x, rel_y, width, depth, height, color)
            # Central Base Station command tower (Golden / Slate glow)
            (0, 0, 8, 8, 35, (0.20, 0.35, 0.50, 1.0)),
            (-14, 0, 6, 6, 25, (0.45, 0.45, 0.48, 1.0)),
            (14, -4, 7, 7, 28, (0.40, 0.42, 0.46, 1.0)),
            (4, 14, 5, 5, 22, (0.42, 0.45, 0.42, 1.0)),
            (-12, -14, 6, 6, 16, (0.48, 0.46, 0.44, 1.0)),
            (12, 12, 5, 5, 18, (0.44, 0.44, 0.48, 1.0)),
            (-8, 11, 4, 4, 14, (0.46, 0.46, 0.45, 1.0)),
            (18, -14, 8, 8, 3, (0.25, 0.25, 0.28, 1.0)),
            (-18, 9, 8, 8, 3, (0.25, 0.25, 0.28, 1.0)),
        ]
        for x, y, w, d, h, rgba in configs:
            half = [w / 2.0, d / 2.0, h / 2.0]
            col = p.createCollisionShape(p.GEOM_BOX, halfExtents=half, physicsClientId=self.client_id)
            vis = p.createVisualShape(p.GEOM_BOX, halfExtents=half, rgbaColor=rgba, physicsClientId=self.client_id)
            base_pos = [self.center[0] + x, self.center[1] + y, h / 2.0]
            bid = p.createMultiBody(
                baseMass=0.0,
                baseCollisionShapeIndex=col,
                baseVisualShapeIndex=vis,
                basePosition=base_pos,
                physicsClientId=self.client_id,
            )
            self.buildings.append(bid)


# ==============================================================================
# UAV Physical Representation
# ==============================================================================

class DroneBody:
    """Represents a physical UAV in PyBullet with visual trust indicator."""

    # Colors as defined in Paper Fig. 1: Trusted drones in green, malicious in black/red
    COLOR_TRUSTED = [0.1, 0.88, 0.25, 1.0]     # Green: Legitimate authenticated UAV
    COLOR_AUTHENTICATING = [1.0, 0.85, 0.0, 1.0] # Yellow: Authenticating in flight
    COLOR_MALICIOUS = [0.15, 0.15, 0.18, 1.0]   # Black / Charcoal: Rogue / Cloned UAV
    COLOR_QUARANTINED = [0.95, 0.1, 0.1, 1.0]   # Red: Attack detected, quarantined

    def __init__(
        self,
        drone_id: int,
        client_id: int,
        initial_pos: Tuple[float, float, float],
        is_trusted: bool = True,
    ):
        self.drone_id = drone_id
        self.client_id = client_id
        self.x, self.y, self.z = initial_pos

        self.target_radius = math.sqrt(self.x * self.x + self.y * self.y)
        self.theta = math.atan2(self.y, self.x)
        self.target_altitude = self.z
        self.speed = 0.5  # rad/s

        self.is_trusted = is_trusted
        self.is_falling = False
        self.state = "TRUSTED" if is_trusted else "APPLICANT"

        self.body_id = self._create_body()

    def _create_body(self) -> int:
        radius = 0.85
        color = self.COLOR_TRUSTED if self.is_trusted else self.COLOR_AUTHENTICATING
        col = p.createCollisionShape(p.GEOM_SPHERE, radius=radius, physicsClientId=self.client_id)
        vis = p.createVisualShape(p.GEOM_SPHERE, radius=radius, rgbaColor=color, physicsClientId=self.client_id)
        body = p.createMultiBody(
            baseMass=1.0,
            baseCollisionShapeIndex=col,
            baseVisualShapeIndex=vis,
            basePosition=[self.x, self.y, self.z],
            physicsClientId=self.client_id,
        )
        return body

    def set_color(self, rgba: List[float]) -> None:
        p.changeVisualShape(self.body_id, -1, rgbaColor=rgba, physicsClientId=self.client_id)

    def update_physics(self, dt: float, orbit_center: Tuple[float, float] = (0.0, 0.0)) -> None:
        if self.is_falling:
            self.z = max(0.4, self.z - 9.8 * dt * 2.5)
            self._apply_position()
            return

        if self.state in ("TRUSTED", "ORBITING"):
            self.theta += self.speed * dt
            self.x = orbit_center[0] + self.target_radius * math.cos(self.theta)
            self.y = orbit_center[1] + self.target_radius * math.sin(self.theta)
            self._apply_position()
        elif self.state == "APPLICANT":
            current_r = math.sqrt(self.x * self.x + self.y * self.y)
            if current_r > self.target_radius:
                dr = 10.0 * dt
                new_r = max(self.target_radius, current_r - dr)
                self.x = new_r * math.cos(self.theta)
                self.y = new_r * math.sin(self.theta)
                self._apply_position()

    def _apply_position(self) -> None:
        orn = p.getQuaternionFromEuler([0, 0, self.theta], physicsClientId=self.client_id)
        p.resetBasePositionAndOrientation(
            self.body_id,
            [self.x, self.y, self.z],
            orn,
            physicsClientId=self.client_id,
        )


# ==============================================================================
# Simulation Controller
# ==============================================================================

class SwarmSimulation:
    """Coordinates PyBullet 3D swarm and Threshold UAV Authentication Engine."""

    def __init__(
        self,
        gui_mode: bool = True,
        threshold_t: int = 3,
        challenge_count_k: int = 6,
        initial_swarm_size: int = 5,
        mode: ProtocolMode = ProtocolMode.DECENTRALIZED_QUORUM,
    ):
        self.gui_mode = gui_mode
        self.t = threshold_t
        self.k = challenge_count_k
        self.n = initial_swarm_size
        if isinstance(mode, ProtocolMode):
            self.mode = mode
        elif isinstance(mode, str):
            val_norm = mode.upper().strip()
            self.mode = ProtocolMode.BASE_STATION if val_norm == "BASE_STATION" else ProtocolMode.DECENTRALIZED_QUORUM
        else:
            self.mode = ProtocolMode.DECENTRALIZED_QUORUM
        self.orbit_radius = 24.0
        self.orbit_altitude = 40.0

        # PyBullet initialization
        conn_type = p.GUI if gui_mode else p.DIRECT
        self.client_id = p.connect(conn_type)
        p.setAdditionalSearchPath(pybullet_data.getDataPath())
        p.setGravity(0, 0, -9.8, physicsClientId=self.client_id)
        p.loadURDF("plane.urdf", physicsClientId=self.client_id)

        # 3D urban environment & Base Station tower
        self.city = BuildingComplex(self.client_id, center=(0.0, 0.0))

        # Base Station protocol engine
        self.base_station = BaseStation(prime=PRIME_P)

        # Verifiable Secret Sharing & Swarm Quorum Setup
        self.vss = VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P)
        self.master_secret = random_secret(PRIME_P)
        self.poly, self.commitments = self.vss.create_polynomial_and_commitments(self.master_secret, self.t)
        self.quorum_coordinator = DecentralizedQuorumCoordinator(threshold_t=self.t, commitments=self.commitments, prime=PRIME_P)
        self.peer_nodes: Dict[int, SwarmPeerNode] = {}

        # Swarm UAV entities
        self.uav_nodes: Dict[int, UAV] = {}
        self.drones: Dict[int, DroneBody] = {}
        self.next_drone_id = 1

        # Periodic re-verification timer
        self.last_reverification_time = time.time()
        self.reverification_interval = 25.0  # seconds

        # Deploy and enroll initial swarm
        self._init_initial_swarm()

        # GUI controls
        self.btn_reverify = None
        self.btn_add_uav = None
        self.btn_attack = None
        self.btn_remove = None
        self.btn_toggle_mode = None
        self.cam_dist = None
        self.cam_yaw = None
        self.cam_pitch = None
        self.hud_text_id = -1
        self._last_btn_states = {}

        if self.gui_mode:
            self._setup_gui()

        # Attack scenario rotation
        self.attack_types = [
            "cloned_puf",
            "replay_attack",
            "mitm_tamper",
            "captured_excess_noise",
            "poisoned_quorum_share",
        ]
        self.attack_idx = 0
        self.last_status_message = f"Topology: {self.mode.value} | Threshold t={self.t}, k={self.k}"

    def _init_initial_swarm(self):
        """Enroll and authenticate initial fleet of legitimate UAVs."""
        for _ in range(self.n):
            u_id = self.next_drone_id
            self.next_drone_id += 1

            # Unique hardware PUF
            puf_seed = secrets.token_bytes(32)
            uav_puf = SRAMPUF(seed=puf_seed, bit_flip_rate=SRAMPUF.PRESET_IDEAL)
            uav_node = UAV(uav_id=u_id, puf=uav_puf, threshold_t=self.t, challenge_count_k=self.k)
            self.uav_nodes[u_id] = uav_node

            # Factory enrollment at Base Station
            init_c = [secrets.token_bytes(16) for _ in range(self.k)]
            enroll_resp = uav_puf.evaluate_set(init_c, noise_override=0.0)
            self.base_station.enroll_uav(u_id, self.t, self.k, enroll_resp, challenges=init_c)
            self.quorum_coordinator.register_uav(u_id, uav_puf)

            # Quorum peer node enrollment
            px = u_id * 37
            py = self.poly.evaluate(px)
            peer = SwarmPeerNode(peer_id=u_id, share_x=px, share_y=py, commitments=self.commitments, puf=uav_puf, prime=PRIME_P)
            self.peer_nodes[u_id] = peer

            # Spawn 3D body
            theta = (2 * math.pi * (u_id - 1)) / self.n
            x = self.orbit_radius * math.cos(theta)
            y = self.orbit_radius * math.sin(theta)
            z = self.orbit_altitude

            body = DroneBody(u_id, self.client_id, (x, y, z), is_trusted=True)
            self.drones[u_id] = body

            # Perform initial authentication
            self._authenticate_uav_session(u_id, uav_node)

    def _authenticate_uav_session(
        self,
        uav_id: int,
        uav_node: UAV,
        noise_override: Optional[float] = None,
        faulty_indices: Optional[List[int]] = None,
        tamper_mac_bs: bool = False,
        tamper_mac_uav: bool = False,
        replay_nonce: bool = False,
        majority_votes: int = 7,
        tamper_peer_id: Optional[int] = None,
    ) -> Tuple[bool, str, float]:
        """Runs mutual authentication (Decentralized Quorum or Base Station mode)."""
        t0 = time.perf_counter()

        target_drone = self.drones.get(uav_id)
        target_pos = (target_drone.x, target_drone.y, target_drone.z) if target_drone else (0.0, 0.0, self.orbit_altitude)

        # Mode 1: Decentralized Peer Quorum
        if self.mode == ProtocolMode.DECENTRALIZED_QUORUM:
            quorum_peers = [p for pid, p in self.peer_nodes.items() if pid != uav_id][:self.k]
            if len(quorum_peers) < self.t:
                return False, f"Insufficient quorum peers ({len(quorum_peers)} < t={self.t})", (time.perf_counter() - t0) * 1000

            # Draw peer-to-peer telemetry lines
            if self.gui_mode:
                for peer in quorum_peers:
                    peer_drone = self.drones.get(peer.peer_id)
                    if peer_drone:
                        self.draw_peer_telemetry_beam((peer_drone.x, peer_drone.y, peer_drone.z), target_pos, [0.2, 0.7, 1.0])

            result = self.quorum_coordinator.coordinate_admission(
                applicant=uav_node,
                quorum_peers=quorum_peers,
                tamper_peer_id=tamper_peer_id,
                replay_nonce=replay_nonce,
                noise_override=noise_override,
                faulty_applicant_indices=faulty_indices,
                tamper_mac_bs=tamper_mac_bs,
                tamper_mac_uav=tamper_mac_uav,
            )

            if not result.admitted:
                if result.quarantined_peers:
                    for q_id in result.quarantined_peers:
                        if q_id in self.drones:
                            self.drones[q_id].set_color(DroneBody.COLOR_QUARANTINED)
                return False, result.reason, result.latency_ms

            if self.gui_mode:
                for peer in quorum_peers:
                    peer_drone = self.drones.get(peer.peer_id)
                    if peer_drone:
                        self.draw_peer_telemetry_beam((peer_drone.x, peer_drone.y, peer_drone.z), target_pos, [0.1, 0.9, 0.3])

            return True, "Decentralized Quorum Admission verified", result.latency_ms

        # Mode 2: Centralized Base Station
        m1 = uav_node.initiate_auth()
        if replay_nonce:
            m1.n_a = b"\xde\xad\xbe\xef" * 4
            self.base_station.nonce_cache.add(m1.n_a)

        ok1, m2, err1 = self.base_station.process_m1(m1)
        if not ok1:
            return False, err1, (time.perf_counter() - t0) * 1000

        if tamper_mac_bs:
            m2.mac_bs = bytes([b ^ 0xFF for b in m2.mac_bs])

        ok2, m3, sk_uav, err2 = uav_node.process_m2(
            m2,
            noise_override=noise_override,
            faulty_indices=faulty_indices,
            majority_votes=majority_votes,
        )
        if not ok2:
            return False, err2, (time.perf_counter() - t0) * 1000

        if tamper_mac_uav:
            m3.mac_uav = bytes([b ^ 0xAA for b in m3.mac_uav])

        ok3, sk_bs, err3 = self.base_station.process_m3(uav_id, m3)
        if not ok3:
            return False, err3, (time.perf_counter() - t0) * 1000

        if sk_uav != sk_bs:
            return False, "Session key mismatch between UAV and Base Station", (time.perf_counter() - t0) * 1000

        elapsed = (time.perf_counter() - t0) * 1000
        return True, "Mutual authentication successful & state ratcheted", elapsed

    def _setup_gui(self):
        p.resetDebugVisualizerCamera(
            cameraDistance=75,
            cameraYaw=45,
            cameraPitch=-30,
            cameraTargetPosition=[0, 0, 18],
            physicsClientId=self.client_id,
        )
        self.cam_dist = p.addUserDebugParameter("Camera Distance", 30, 140, 75, physicsClientId=self.client_id)
        self.cam_yaw = p.addUserDebugParameter("Camera Yaw", -180, 180, 45, physicsClientId=self.client_id)
        self.cam_pitch = p.addUserDebugParameter("Camera Pitch", -89, 0, -30, physicsClientId=self.client_id)

        self.btn_reverify = p.addUserDebugParameter("Periodic Re-verification", 0, 1, 0, physicsClientId=self.client_id)
        self.btn_add_uav = p.addUserDebugParameter("Join Legitimate UAV", 0, 1, 0, physicsClientId=self.client_id)
        self.btn_attack = p.addUserDebugParameter("Simulate Rogue Attack", 0, 1, 0, physicsClientId=self.client_id)
        self.btn_remove = p.addUserDebugParameter("Remove UAV", 0, 1, 0, physicsClientId=self.client_id)
        self.btn_toggle_mode = p.addUserDebugParameter("Toggle Topology Mode", 0, 1, 0, physicsClientId=self.client_id)

        self._last_btn_states = {
            "reverify": p.readUserDebugParameter(self.btn_reverify, physicsClientId=self.client_id),
            "add": p.readUserDebugParameter(self.btn_add_uav, physicsClientId=self.client_id),
            "attack": p.readUserDebugParameter(self.btn_attack, physicsClientId=self.client_id),
            "remove": p.readUserDebugParameter(self.btn_remove, physicsClientId=self.client_id),
            "mode": p.readUserDebugParameter(self.btn_toggle_mode, physicsClientId=self.client_id),
        }

    def _update_hud(self):
        if not self.gui_mode:
            return

        trusted_count = sum(1 for d in self.drones.values() if d.is_trusted and not d.is_falling)
        quarantined_count = sum(1 for state in self.base_station.enrolled_uavs.values() if state.quarantined)

        hud_str = (
            f"UAV SWARM AUTH | Mode: {self.mode.value} | Sec Level: {self.t * 100 // self.k}% (t={self.t}, k={self.k}) | "
            f"Trusted: {trusted_count} (Green) | Malicious: {quarantined_count} (Red) | {self.last_status_message}"
        )
        if self.hud_text_id != -1:
            p.removeUserDebugItem(self.hud_text_id, physicsClientId=self.client_id)

        color = [0.1, 0.9, 0.3] if quarantined_count == 0 else [1.0, 0.3, 0.2]
        self.hud_text_id = p.addUserDebugText(
            hud_str,
            [-28, -28, 48],
            textColorRGB=color,
            textSize=1.1,
            physicsClientId=self.client_id,
        )

    def draw_telemetry_beam(self, target_pos: Tuple[float, float, float], color: List[float]):
        """Draw 3D laser telemetry line between Base Station tower and UAV."""
        if not self.gui_mode:
            return
        bs_pos = [0.0, 0.0, 35.0]  # Top of Base Station tower
        p.addUserDebugLine(
            bs_pos,
            list(target_pos),
            lineColorRGB=color,
            lineWidth=3.0,
            lifeTime=2.0,
            physicsClientId=self.client_id,
        )

    def draw_peer_telemetry_beam(self, from_pos: Tuple[float, float, float], to_pos: Tuple[float, float, float], color: List[float]):
        """Draw 3D laser telemetry line directly between swarm peer drones."""
        if not self.gui_mode:
            return
        p.addUserDebugLine(
            list(from_pos),
            list(to_pos),
            lineColorRGB=color,
            lineWidth=3.0,
            lifeTime=1.5,
            physicsClientId=self.client_id,
        )

    def trigger_periodic_reverification(self):
        """Re-verifies all active swarm UAVs and ratchets their state."""
        print("\n>>> [BS COMMAND] Triggering Periodic Re-verification across all swarm UAVs...")
        verified = 0
        total_time = 0.0

        for u_id, uav_node in list(self.uav_nodes.items()):
            drone_body = self.drones.get(u_id)
            if not drone_body or drone_body.is_falling:
                continue

            ok, reason, latency = self._authenticate_uav_session(u_id, uav_node)
            total_time += latency
            if ok:
                verified += 1
                self.draw_telemetry_beam((drone_body.x, drone_body.y, drone_body.z), [0.1, 0.9, 0.3])
                drone_body.set_color(DroneBody.COLOR_TRUSTED)
            else:
                drone_body.set_color(DroneBody.COLOR_QUARANTINED)
                drone_body.is_falling = True

        self.last_status_message = f"Periodic re-verification: {verified} UAVs verified in {total_time:.2f} ms"
        print(f"    [OK] {self.last_status_message}")

    def add_legitimate_uav(self):
        """Spawns an applicant UAV, factory-enrolls its PUF, authenticates, and joins orbit."""
        new_id = self.next_drone_id
        self.next_drone_id += 1
        print(f"\n>>> [ENROLLMENT] Deploying Legitimate UAV {new_id}...")

        spawn_r = self.orbit_radius + 18.0
        angle = random.uniform(0, 2 * math.pi)
        spawn_pos = (spawn_r * math.cos(angle), spawn_r * math.sin(angle), self.orbit_altitude)

        drone_body = DroneBody(new_id, self.client_id, spawn_pos, is_trusted=False)
        self.drones[new_id] = drone_body

        # Factory enrollment
        uav_puf = SRAMPUF(seed=secrets.token_bytes(32), bit_flip_rate=SRAMPUF.PRESET_NORMAL)
        uav_node = UAV(uav_id=new_id, puf=uav_puf, threshold_t=self.t, challenge_count_k=self.k)
        self.uav_nodes[new_id] = uav_node

        init_c = [secrets.token_bytes(16) for _ in range(self.k)]
        enroll_resp = uav_puf.evaluate_set(init_c, noise_override=0.0)
        self.base_station.enroll_uav(new_id, self.t, self.k, enroll_resp, challenges=init_c)
        self.quorum_coordinator.register_uav(new_id, uav_puf)

        px = new_id * 37
        py = self.poly.evaluate(px)
        peer = SwarmPeerNode(peer_id=new_id, share_x=px, share_y=py, commitments=self.commitments, puf=uav_puf, prime=PRIME_P)
        self.peer_nodes[new_id] = peer

        # Authenticate
        ok, reason, latency = self._authenticate_uav_session(new_id, uav_node)
        if ok:
            drone_body.is_trusted = True
            drone_body.state = "TRUSTED"
            drone_body.target_radius = self.orbit_radius
            drone_body.set_color(DroneBody.COLOR_TRUSTED)
            self.draw_telemetry_beam(spawn_pos, [0.1, 0.9, 0.3])
            self.last_status_message = f"UAV {new_id} Authenticated & Admitted in {latency:.2f} ms"
            print(f"    [OK] ADMISSION SUCCESS: UAV {new_id} verified via Shamir ({self.t}/{self.k}) in {latency:.2f} ms.")
        else:
            drone_body.set_color(DroneBody.COLOR_QUARANTINED)
            drone_body.is_falling = True
            self.last_status_message = f"UAV {new_id} Rejected: {reason}"
            print(f"    [ALERT] ADMISSION FAILED: {reason}")

    def simulate_attack(self) -> Tuple[str, bool, str]:
        """Demonstrates security resistance against various adversarial threats."""
        attack_type = self.attack_types[self.attack_idx]
        self.attack_idx = (self.attack_idx + 1) % len(self.attack_types)

        rogue_id = self.next_drone_id
        self.next_drone_id += 1

        print(f"\n>>> [SECURITY THREAT] Triggering Adversarial Attack: {attack_type.upper()} with Rogue UAV {rogue_id}...")

        spawn_r = self.orbit_radius + 15.0
        angle = random.uniform(0, 2 * math.pi)
        spawn_pos = (spawn_r * math.cos(angle), spawn_r * math.sin(angle), self.orbit_altitude)

        drone_body = DroneBody(rogue_id, self.client_id, spawn_pos, is_trusted=False)
        # Malicious drones represented in Black/Charcoal (Paper Fig. 1)
        drone_body.set_color(DroneBody.COLOR_MALICIOUS)
        self.drones[rogue_id] = drone_body

        ok = False
        reason = ""
        latency = 0.0

        if attack_type == "cloned_puf":
            # Attacker fabricates drone with wrong PUF silicon seed
            legit_puf = SRAMPUF(seed=b"GENUINE_ORIGINAL_SEED_12345", bit_flip_rate=0.0)
            fake_puf = SRAMPUF(seed=b"ROGUE_FABRICATED_PUF_SEED_9999", bit_flip_rate=0.0)

            init_c = [secrets.token_bytes(16) for _ in range(self.k)]
            self.base_station.enroll_uav(rogue_id, self.t, self.k, legit_puf.evaluate_set(init_c), challenges=init_c)
            self.quorum_coordinator.register_uav(rogue_id, legit_puf)

            rogue_node = UAV(uav_id=rogue_id, puf=fake_puf, threshold_t=self.t, challenge_count_k=self.k)
            ok, reason, latency = self._authenticate_uav_session(rogue_id, rogue_node)

        elif attack_type == "replay_attack":
            # Replays an intercepted M1 nonce
            puf = SRAMPUF(seed=secrets.token_bytes(32), bit_flip_rate=0.0)
            init_c = [secrets.token_bytes(16) for _ in range(self.k)]
            self.base_station.enroll_uav(rogue_id, self.t, self.k, puf.evaluate_set(init_c), challenges=init_c)
            self.quorum_coordinator.register_uav(rogue_id, puf)
            node = UAV(uav_id=rogue_id, puf=puf, threshold_t=self.t, challenge_count_k=self.k)
            ok, reason, latency = self._authenticate_uav_session(rogue_id, node, replay_nonce=True)

        elif attack_type == "mitm_tamper":
            # Man-in-the-middle alters MAC or challenge in transit
            puf = SRAMPUF(seed=secrets.token_bytes(32), bit_flip_rate=0.0)
            init_c = [secrets.token_bytes(16) for _ in range(self.k)]
            self.base_station.enroll_uav(rogue_id, self.t, self.k, puf.evaluate_set(init_c), challenges=init_c)
            self.quorum_coordinator.register_uav(rogue_id, puf)
            node = UAV(uav_id=rogue_id, puf=puf, threshold_t=self.t, challenge_count_k=self.k)
            ok, reason, latency = self._authenticate_uav_session(rogue_id, node, tamper_mac_bs=True)

        elif attack_type == "poisoned_quorum_share":
            # Adversary corrupts a peer to inject a poisoned share into admission
            puf = SRAMPUF(seed=secrets.token_bytes(32), bit_flip_rate=0.0)
            init_c = [secrets.token_bytes(16) for _ in range(self.k)]
            self.base_station.enroll_uav(rogue_id, self.t, self.k, puf.evaluate_set(init_c), challenges=init_c)
            self.quorum_coordinator.register_uav(rogue_id, puf)
            node = UAV(uav_id=rogue_id, puf=puf, threshold_t=self.t, challenge_count_k=self.k)
            malicious_peer_id = list(self.peer_nodes.keys())[0] if self.peer_nodes else None
            ok, reason, latency = self._authenticate_uav_session(rogue_id, node, tamper_peer_id=malicious_peer_id)

        else:  # captured_excess_noise
            # Severe physical damage causing > k-t response errors
            puf = SRAMPUF(seed=secrets.token_bytes(32), bit_flip_rate=0.0)
            init_c = [secrets.token_bytes(16) for _ in range(self.k)]
            self.base_station.enroll_uav(rogue_id, self.t, self.k, puf.evaluate_set(init_c), challenges=init_c)
            self.quorum_coordinator.register_uav(rogue_id, puf)
            node = UAV(uav_id=rogue_id, puf=puf, threshold_t=self.t, challenge_count_k=self.k)
            # Inject k-t+1 faults (e.g. 4 faults when k=6, t=3, max allowed is 3)
            excess_faults = list(range(self.k - self.t + 1))
            ok, reason, latency = self._authenticate_uav_session(rogue_id, node, faulty_indices=excess_faults)

        # Attacker rejected -> turns Red and drops out
        drone_body.set_color(DroneBody.COLOR_QUARANTINED)
        drone_body.is_falling = True
        self.draw_telemetry_beam(spawn_pos, [1.0, 0.1, 0.1])
        self.last_status_message = f"ATTACK BLOCKED ({attack_type}): {reason}"
        print(f"    [ALERT] ATTACK THWARTED: {attack_type} -> {reason}")

        return attack_type, ok, reason

    def remove_uav(self) -> Optional[int]:
        candidates = [u_id for u_id, d in self.drones.items() if d.is_trusted and not d.is_falling]
        if candidates:
            rm_id = max(candidates)
            self.drones[rm_id].is_falling = True
            self.drones[rm_id].is_trusted = False
            self.last_status_message = f"UAV {rm_id} departed swarm."
            print(f"\n[-] UAV {rm_id} departed swarm formation.")
            return rm_id
        return None

    def step(self, dt: float = 1.0 / 60.0):
        for drone in self.drones.values():
            drone.update_physics(dt)

        if self.gui_mode:
            dist = p.readUserDebugParameter(self.cam_dist, physicsClientId=self.client_id)
            yaw = p.readUserDebugParameter(self.cam_yaw, physicsClientId=self.client_id)
            pitch = p.readUserDebugParameter(self.cam_pitch, physicsClientId=self.client_id)
            p.resetDebugVisualizerCamera(dist, yaw, pitch, [0, 0, 18], physicsClientId=self.client_id)

            curr_rev = p.readUserDebugParameter(self.btn_reverify, physicsClientId=self.client_id)
            curr_add = p.readUserDebugParameter(self.btn_add_uav, physicsClientId=self.client_id)
            curr_atk = p.readUserDebugParameter(self.btn_attack, physicsClientId=self.client_id)
            curr_rm = p.readUserDebugParameter(self.btn_remove, physicsClientId=self.client_id)
            curr_mode = p.readUserDebugParameter(self.btn_toggle_mode, physicsClientId=self.client_id)

            if curr_rev != self._last_btn_states["reverify"]:
                self._last_btn_states["reverify"] = curr_rev
                self.trigger_periodic_reverification()

            if curr_add != self._last_btn_states["add"]:
                self._last_btn_states["add"] = curr_add
                self.add_legitimate_uav()

            if curr_atk != self._last_btn_states["attack"]:
                self._last_btn_states["attack"] = curr_atk
                self.simulate_attack()

            if curr_rm != self._last_btn_states["remove"]:
                self._last_btn_states["remove"] = curr_rm
                self.remove_uav()

            if curr_mode != self._last_btn_states["mode"]:
                self._last_btn_states["mode"] = curr_mode
                if self.mode == ProtocolMode.DECENTRALIZED_QUORUM:
                    self.mode = ProtocolMode.BASE_STATION
                    self.last_status_message = "Switched to BASE STATION mode"
                else:
                    self.mode = ProtocolMode.DECENTRALIZED_QUORUM
                    self.last_status_message = "Switched to DECENTRALIZED QUORUM mode"
                print(f"\n[TOPOLOGY TOGGLE] {self.last_status_message}")

            self._update_hud()

        # Periodic re-verification check
        if time.time() - self.last_reverification_time > self.reverification_interval:
            self.last_reverification_time = time.time()
            self.trigger_periodic_reverification()

        p.stepSimulation(physicsClientId=self.client_id)

    def run_loop(self):
        print("\n" + "=" * 76)
        print("   [SIM] UAV SWARM AUTHENTICATION SIMULATION")
        print("   PyBullet 3D Swarm & PUF-Enabled Drone Fleet")
        print("=" * 76)
        print(f"   Swarm Fleet: {self.n} UAVs | Threshold t: {self.t} | Challenges k: {self.k}")
        print(f"   Topology Mode: {self.mode.value} | Security Level: {self.t * 100 // self.k}%")
        print("=" * 76 + "\n")

        dt = 1.0 / 60.0
        try:
            while p.isConnected(self.client_id):
                self.step(dt)
                time.sleep(dt)
        except KeyboardInterrupt:
            print("\n[EXIT] Simulation interrupted by user.")
        finally:
            if p.isConnected(self.client_id):
                p.disconnect(self.client_id)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="UAV Swarm Authentication Simulation")
    parser.add_argument("--headless", action="store_true", help="Run without OpenGL GUI")
    parser.add_argument("--mode", type=str, choices=["base_station", "decentralized_quorum"], default="decentralized_quorum", help="Protocol topology mode")
    parser.add_argument("--t", type=int, default=3, help="Shamir threshold t")
    parser.add_argument("--k", type=int, default=6, help="Challenge count k")
    parser.add_argument("--n", type=int, default=5, help="Initial swarm size n")
    args = parser.parse_args()

    mode_enum = ProtocolMode.BASE_STATION if args.mode == "base_station" else ProtocolMode.DECENTRALIZED_QUORUM
    sim = SwarmSimulation(
        gui_mode=not args.headless,
        threshold_t=args.t,
        challenge_count_k=args.k,
        initial_swarm_size=args.n,
        mode=mode_enum,
    )
    sim.run_loop()


if __name__ == "__main__":
    main()
