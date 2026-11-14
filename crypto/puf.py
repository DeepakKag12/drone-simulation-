"""
SRAM PUF (Physically Unclonable Function) Simulator with Bit-Flip Noise Model.

Models silicon hardware intrinsics based on manufacturing process variations:
- Deterministic 320-bit (40 bytes) base response per (seed, challenge).
- Per-bit flip probability p re-sampled on every evaluation.
- Realistic environmental presets:
  * IDEAL (0% flip rate): Controlled laboratory benchmark.
  * NORMAL (~2% flip rate): Standard operating conditions.
  * HOT_LOW_VOLTAGE (~5% flip rate): High thermal stress / voltage drop.
  * AGED (~10% flip rate): Silicon degradation after prolonged deployment.
"""

import hashlib
import hmac
import random
import secrets
from typing import List, Optional, Sequence, Union


class SRAMPUF:
    """
    SRAM Physically Unclonable Function (PUF) Simulator.
    Generates 320-bit responses with stochastic bit-flip variations.
    """

    PRESET_IDEAL: float = 0.00
    PRESET_NORMAL: float = 0.02
    PRESET_HOT_LOW_VOLTAGE: float = 0.05
    PRESET_AGED: float = 0.10

    RESPONSE_BITS: int = 320
    RESPONSE_BYTES: int = 40

    def __init__(
        self,
        seed: Optional[Union[bytes, str, int]] = None,
        bit_flip_rate: float = PRESET_IDEAL,
    ):
        """
        Initialize the PUF with a unique silicon fingerprint seed.
        """
        if seed is None:
            self.seed = secrets.token_bytes(32)
        elif isinstance(seed, str):
            self.seed = hashlib.sha256(seed.encode("utf-8")).digest()
        elif isinstance(seed, int):
            self.seed = seed.to_bytes(32, byteorder="big", signed=False)
        else:
            self.seed = bytes(seed)

        self.bit_flip_rate = float(bit_flip_rate)

    def set_environment_preset(self, preset_name: str) -> None:
        """Configure environmental noise preset."""
        presets = {
            "ideal": self.PRESET_IDEAL,
            "normal": self.PRESET_NORMAL,
            "hot": self.PRESET_HOT_LOW_VOLTAGE,
            "hot_low_voltage": self.PRESET_HOT_LOW_VOLTAGE,
            "aged": self.PRESET_AGED,
        }
        name_lower = preset_name.lower().strip()
        if name_lower in presets:
            self.bit_flip_rate = presets[name_lower]
        else:
            raise ValueError(f"Unknown preset '{preset_name}'. Options: {list(presets.keys())}")

    def compute_base_response(self, challenge: bytes) -> bytes:
        """
        Compute deterministic 320-bit (40 bytes) base response from (seed, challenge).
        Derived using HMAC-SHA256 (32 bytes) + HMAC-SHA256 counter 2 (8 bytes).
        """
        if not isinstance(challenge, bytes):
            challenge = str(challenge).encode("utf-8")

        b1 = hmac.new(self.seed, challenge + b"\x01", hashlib.sha256).digest()
        b2 = hmac.new(self.seed, challenge + b"\x02", hashlib.sha256).digest()
        base_320 = b1 + b2[:8]
        assert len(base_320) == self.RESPONSE_BYTES, f"Base response must be 40 bytes, got {len(base_320)}"
        return base_320

    def evaluate(
        self,
        challenge: bytes,
        noise_override: Optional[float] = None,
        force_corrupt: bool = False,
        majority_votes: int = 1,
    ) -> bytes:
        """
        Evaluate the PUF on challenge, applying stochastic bit-flip noise.

        :param challenge: Challenge byte string.
        :param noise_override: If provided, overrides instance bit_flip_rate.
        :param force_corrupt: If True, guarantees at least one inverted bit.
        :param majority_votes: Number of reads simulated for majority voting.
                               e.g., 5-7 rounds of on-chip temporal sampling.
        :return: 40-byte (320-bit) evaluated response.
        """
        base = self.compute_base_response(challenge)
        p_flip = self.bit_flip_rate if noise_override is None else float(noise_override)

        if p_flip <= 0.0 and not force_corrupt:
            return base

        # Convert base bytes to mutable bit array
        bits = []
        for byte_val in base:
            for shift in range(7, -1, -1):
                bits.append((byte_val >> shift) & 1)

        # Apply noise model
        flipped_any = False
        for i in range(len(bits)):
            if majority_votes > 1:
                # Majority voting across multiple temporal reads
                votes_flipped = sum(1 for _ in range(majority_votes) if random.random() < p_flip)
                should_flip = (votes_flipped > (majority_votes // 2))
            else:
                should_flip = (random.random() < p_flip)

            if should_flip:
                bits[i] ^= 1
                flipped_any = True

        if force_corrupt and not flipped_any:
            # Force at least one bit flip if explicitly requested
            target_idx = random.randrange(len(bits))
            bits[target_idx] ^= 1

        # Reconstruct byte array from bits
        out_bytes = bytearray(self.RESPONSE_BYTES)
        for i in range(len(bits)):
            byte_idx = i // 8
            bit_offset = 7 - (i % 8)
            out_bytes[byte_idx] |= (bits[i] << bit_offset)

        return bytes(out_bytes)

    def evaluate_set(
        self,
        challenges: Sequence[bytes],
        noise_override: Optional[float] = None,
        faulty_indices: Optional[Sequence[int]] = None,
        majority_votes: int = 1,
    ) -> List[bytes]:
        """
        Evaluate a sequence of challenges.
        If faulty_indices is specified, forces corruption on those exact indices.
        """
        responses = []
        fault_set = set(faulty_indices) if faulty_indices is not None else set()

        for j, c in enumerate(challenges):
            if j in fault_set:
                resp = self.evaluate(c, force_corrupt=True)
            else:
                resp = self.evaluate(
                    c,
                    noise_override=noise_override,
                    majority_votes=majority_votes,
                )
            responses.append(resp)
        return responses

    def clone(self) -> "SRAMPUF":
        """Produce an identical PUF instance with the same seed (for cloning attack tests)."""
        return SRAMPUF(seed=self.seed, bit_flip_rate=self.bit_flip_rate)

