"""
Unified Entry Point for UAV Swarm Authentication System.

Usage:
  python main.py --sim           # Run 3D PyBullet Swarm Visual Simulation
  python main.py --sim --headless# Run 3D Swarm Simulation in Headless Mode
  python main.py --test          # Run Complete Cryptographic Verification Test Suite
  python main.py --demo          # Step-by-Step Terminal Cryptography Walkthrough
  python main.py --eval          # Run Benchmarks & Save Results to /results
"""

import argparse
import json
import os
import secrets
import sys
import time

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


def run_demo(mode: str = "decentralized_quorum"):
    """Terminal walkthrough of UAV Authentication Protocol with Architectural Upgrades."""
    from crypto.finite_field import (
        PRIME_P,
        COMMITMENT_PRIME_P,
        COMMITMENT_GENERATOR_G,
        hash_secret,
        random_secret,
    )
    from crypto.puf import SRAMPUF
    from crypto.shamir import (
        Polynomial,
        BarycentricInterpolator,
        VerifiableSecretSharing,
    )
    from crypto.protocol import (
        BaseStation,
        UAV,
        ProtocolMode,
        SwarmPeerNode,
        DecentralizedQuorumCoordinator,
    )

    print("\n" + "=" * 76)
    print("   UAV SWARM AUTHENTICATION PROTOCOL - TERMINAL WALKTHROUGH")
    print("=" * 76)

    # --------------------------------------------------------------------------
    # PART A: BASE STATION MUTUAL AUTHENTICATION & STATE RATCHETING
    # --------------------------------------------------------------------------
    t, k = 4, 8
    print(f"\n[PART A: CENTRALIZED BASE STATION PROTOCOL]")
    print(f"  * Field Modulus p: 2^127 - 1 = {PRIME_P}")
    print(f"  * Challenge Count k: {k}")
    print(f"  * Threshold t: {t} (Security Level: {t * 100 // k}%)")

    bs = BaseStation(prime=PRIME_P)
    puf_seed = secrets.token_bytes(32)
    uav_puf = SRAMPUF(seed=puf_seed, bit_flip_rate=SRAMPUF.PRESET_NORMAL)
    uav_id = 101
    uav = UAV(uav_id=uav_id, puf=uav_puf, threshold_t=t, challenge_count_k=k)

    init_c = [secrets.token_bytes(16) for _ in range(k)]
    enroll_resp = uav_puf.evaluate_set(init_c, noise_override=0.0)
    challenges, state = bs.enroll_uav(uav_id, t, k, enroll_resp, challenges=init_c)
    print(f"  * UAV {uav_id} enrolled at Base Station: H(S) = {state.h_s.hex()[:24]}...")

    # Step 1: UAV -> BS (M1)
    m1 = uav.initiate_auth()
    ok1, m2, err1 = bs.process_m1(m1)
    assert ok1, err1
    print(f"  1. UAV -> BS: [M1] Anti-replay verified with fresh nonce N_A.")

    # Step 2: BS -> UAV (M2) & Step 3: UAV PUF evaluation
    ok2, m3, sk_uav, err2 = uav.process_m2(m2, noise_override=0.0, faulty_indices=[1, 3])
    assert ok2, err2
    print(f"  2. BS -> UAV: [M2] Issued challenges & masked share set.")
    print(f"  3. UAV evaluated PUF with 2 errors: Secret S* reconstructed, MAC_BS verified!")

    # Step 4: UAV -> BS (M3) & Step 5: Session Key
    ok3, sk_bs, err3 = bs.process_m3(uav_id, m3)
    assert ok3, err3
    print(f"  4. UAV -> BS: [M3] Fresh challenges C' and response ciphertext J.")
    print(f"  5. BS verified MAC_UAV: Mutual Session Key Sk = {sk_uav.hex()[:32]}...")
    print(f"  * Key Agreement: Sk_UAV == Sk_BS: {sk_uav == sk_bs}")
    print(f"  * Ratcheting: State updated with fresh CRPs; old secrets destroyed.")

    # --------------------------------------------------------------------------
    # PART B: DECENTRALIZED QUORUM ADMISSION (PHASES 1, 2, 3)
    # --------------------------------------------------------------------------
    print(f"\n" + "-" * 76)
    print(f"[PART B: DECENTRALIZED PEER QUORUM UPGRADE]")
    print(f"  Overcomes Base Station Single-Point-of-Failure & Physical Capture")
    print(f"-" * 76)

    # Phase 3: Setup Verifiable Secret Sharing (VSS) Public Commitments
    print(f"  [Phase 3 Setup] Generating VSS Public Commitments:")
    vss = VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P)
    master_secret = random_secret(PRIME_P)
    poly, commitments = vss.create_polynomial_and_commitments(master_secret, threshold_t=t)
    print(f"  * Public Commitments C_j = g^(a_j) mod P ({len(commitments)} commitments published)")
    print(f"  * Master Commitment C_0 = g^S mod P: {str(commitments[0])[:32]}...")

    # Phase 1: Deploy peer nodes in swarm
    print(f"\n  [Phase 1] Decentralized Peer Quorum Formation:")
    peers = []
    for i in range(1, k + 1):
        px = i * 43
        py = poly.evaluate(px)
        peer = SwarmPeerNode(
            peer_id=200 + i,
            share_x=px,
            share_y=py,
            commitments=commitments,
            puf=SRAMPUF(seed=secrets.token_bytes(32)),
        )
        peers.append(peer)
    print(f"  * {len(peers)} Swarm peer nodes active with validated local shares (x_i, y_i).")

    # Phase 1: Applicant node requests admission
    coordinator = DecentralizedQuorumCoordinator(threshold_t=t, commitments=commitments)
    applicant_puf = SRAMPUF(seed=b"DECENTRALIZED_APPLICANT_KEY", bit_flip_rate=0.0)
    applicant = UAV(uav_id=909, puf=applicant_puf, threshold_t=t, challenge_count_k=k)

    print(f"\n  [Phase 2] Non-Reconstructive Threshold Verification:")
    print(f"  * Quorum peers compute partial tokens locally: sigma_i = y_i * w_i mod p, T_i = g^sigma_i mod P")
    print(f"  * Tokens combined homomorphically at coordinator: prod T_i = g^S mod P == C_0")
    print(f"  * Master secret S is NEVER exposed in plaintext RAM at any leader node!")

    result = coordinator.coordinate_admission(applicant=applicant, quorum_peers=peers)
    assert result.admitted, result.reason
    print(f"  [OK] Autonomous Peer Admission Success: Admitted={result.admitted} ({result.latency_ms:.2f} ms)")
    print(f"  [OK] Derived Quorum Session Key Sk: {result.session_key.hex()[:32]}...")

    # Phase 3 Defense Demonstration: Poisoned share rejection
    print(f"\n  [Phase 3 Defense] Poisoned Share Injection Attempt:")
    tamper_id = 203
    print(f"  * Simulating malicious / compromised Peer {tamper_id} submitting forged share...")
    poison_result = coordinator.coordinate_admission(
        applicant=applicant,
        quorum_peers=peers,
        tamper_peer_id=tamper_id,
    )
    assert not poison_result.admitted
    print(f"  [ALERT] Poisoned share detected on-the-fly via VSS public commitments!")
    print(f"  [ALERT] Quarantined Peer IDs: {poison_result.quarantined_peers}")
    print(f"  * Reason: {poison_result.reason}")
    print("=" * 76 + "\n")


def run_evaluation():
    """Phase 5 Evaluation: Run benchmarks and save results to /results."""
    from crypto.finite_field import PRIME_P, random_secret, hash_secret, hash_to_field, pad_hash, xor_bytes, hkdf_derive_session_key
    from crypto.puf import SRAMPUF
    from crypto.protocol import BaseStation, UAV, compute_mac_bs, compute_mac_uav

    print("\n" + "=" * 76)
    print("   RUNNING UAV PROTOCOL BENCHMARKS & EVALUATION")
    print("=" * 76)

    os.makedirs("results", exist_ok=True)

    # 1. Micro-benchmark of individual primitive operations (Table IV)
    print("  Measuring cryptographic primitive execution times...")
    N_ITER = 5000

    # Ta: Bitwise XOR
    b1 = secrets.token_bytes(40)
    b2 = secrets.token_bytes(40)
    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _ = xor_bytes(b1, b2)
    ta_sec = (time.perf_counter() - t0) / N_ITER

    # Tb: PRNG
    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _ = secrets.token_bytes(16)
    tb_sec = (time.perf_counter() - t0) / N_ITER

    # Tc: Hash (SHA-256)
    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _ = hash_secret(123456789)
    tc_sec = (time.perf_counter() - t0) / N_ITER

    # Td: HMAC (HMAC-SHA256)
    key = secrets.token_bytes(32)
    msg = secrets.token_bytes(128)
    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _ = compute_mac_uav(key, [msg[:40]], msg[40:56])
    td_sec = (time.perf_counter() - t0) / N_ITER

    # Te: PUF evaluation (per response)
    puf = SRAMPUF(seed=b"BENCHMARK_PUF_SEED_12345", bit_flip_rate=0.02)
    chal = secrets.token_bytes(16)
    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _ = puf.evaluate(chal)
    te_sec = (time.perf_counter() - t0) / N_ITER

    # Tf: Concatenation / serialization
    c_list = [secrets.token_bytes(16) for _ in range(8)]
    t0 = time.perf_counter()
    for _ in range(N_ITER):
        _ = b"".join(c_list)
    tf_sec = (time.perf_counter() - t0) / N_ITER

    micro_benchmarks = {
        "Ta_Bitwise_XOR_sec": ta_sec,
        "Tb_PRNG_sec": tb_sec,
        "Tc_Hash_sec": tc_sec,
        "Td_HMAC_sec": td_sec,
        "Te_PUF_sec": te_sec,
        "Tf_Concatenation_sec": tf_sec,
    }

    # 2. Total authentication time vs security level for k=8 and t=2, 4, 6, 8 (25%, 50%, 75%, 100%)
    print("  Measuring protocol execution time across security levels (k=8, t=2,4,6,8)...")
    sec_levels = [
        {"k": 8, "t": 2, "level_pct": 25},
        {"k": 8, "t": 4, "level_pct": 50},
        {"k": 8, "t": 6, "level_pct": 75},
        {"k": 8, "t": 8, "level_pct": 100},
    ]

    perf_results = []
    for cfg in sec_levels:
        t = cfg["t"]
        k = cfg["k"]
        bs = BaseStation()
        puf_inst = SRAMPUF(seed=secrets.token_bytes(32), bit_flip_rate=0.0)
        uav_id = 800 + t
        uav = UAV(uav_id=uav_id, puf=puf_inst, threshold_t=t, challenge_count_k=k)
        init_c = [secrets.token_bytes(16) for _ in range(k)]
        bs.enroll_uav(uav_id, t, k, puf_inst.evaluate_set(init_c), challenges=init_c)

        times = []
        for _ in range(100):
            t_start = time.perf_counter()
            m1 = uav.initiate_auth()
            _, m2, _ = bs.process_m1(m1)
            _, m3, sk1, _ = uav.process_m2(m2)
            _, sk2, _ = bs.process_m3(uav_id, m3)
            elapsed_us = (time.perf_counter() - t_start) * 1e6
            times.append(elapsed_us)

        avg_us = sum(times) / len(times)
        min_us = min(times)
        max_us = max(times)
        perf_results.append({
            "security_level_pct": cfg["level_pct"],
            "threshold_t": t,
            "challenges_k": k,
            "avg_time_us": round(avg_us, 2),
            "min_time_us": round(min_us, 2),
            "max_time_us": round(max_us, 2),
        })

    # 3. Communication and Storage Cost Analysis
    # Message sizes in bits:
    # M1: id (32 bits) + N_A (128 bits) = 160 bits
    # M2: C (k * 128 bits) + Q (256 bits) + L (k * 127 bits) + MAC_BS (256 bits)
    # For k=8: 8*128 + 256 + 8*127 + 256 = 1024 + 256 + 1016 + 256 = 2552 bits (paper claims 1600 bits for k=5)
    # M3: C' (k * 128) + J (k * 320) + P (256) + MAC_UAV (256)
    # UAV storage: id (32 bits) + OTP / seed (256 bits) = ~288 to 352 bits
    costs = {
        "communication_cost_bits_k5": 160 + (5 * 128 + 256 + 5 * 127 + 256) + (5 * 128 + 5 * 320 + 256 + 256),
        "communication_cost_bits_k8": 160 + (8 * 128 + 256 + 8 * 127 + 256) + (8 * 128 + 8 * 320 + 256 + 256),
        "uav_storage_cost_bits": 352,
        "paper_reported_comm_cost_bits": 1600,
        "paper_reported_storage_cost_bits": 352,
        "paper_reported_time_nodemcu_us": 450,
        "paper_reported_time_rpi_us": 207,
    }

    # 4. Success Rate vs Noise for t=3, k=6 (50%) and t=4, k=8 (50%)
    print("  Measuring authentication success rate vs PUF noise rate...")
    noise_rates = [0.0, 0.01, 0.02, 0.03, 0.04, 0.05, 0.08, 0.10]
    success_curve = []

    for nr in noise_rates:
        t, k = 3, 6
        successes = 0
        TRIALS = 50
        for trial in range(TRIALS):
            bs = BaseStation()
            puf_inst = SRAMPUF(seed=secrets.token_bytes(32), bit_flip_rate=nr)
            uav_id = 900 + trial
            uav = UAV(uav_id=uav_id, puf=puf_inst, threshold_t=t, challenge_count_k=k)
            init_c = [secrets.token_bytes(16) for _ in range(k)]
            bs.enroll_uav(uav_id, t, k, puf_inst.evaluate_set(init_c, noise_override=0.0), challenges=init_c)

            m1 = uav.initiate_auth()
            ok1, m2, _ = bs.process_m1(m1)
            # Simulate majority votes = 7 (standard SRAM PUF sampling)
            ok2, m3, sk1, _ = uav.process_m2(m2, majority_votes=7)
            if ok2:
                ok3, sk2, _ = bs.process_m3(uav_id, m3)
                if ok3 and sk1 == sk2:
                    successes += 1

        rate = (successes / TRIALS) * 100.0
        success_curve.append({
            "noise_rate": nr,
            "success_rate_pct": round(rate, 2),
            "trials": TRIALS,
        })

    # 5. False Acceptance Rate (FAR) for wrong / cloned PUF
    print("  Measuring False Acceptance Rate (FAR) for unauthorized PUFs...")
    FAR_TRIALS = 200
    far_accepts = 0
    for i in range(FAR_TRIALS):
        bs = BaseStation()
        legit_puf = SRAMPUF(seed=secrets.token_bytes(32))
        attacker_puf = SRAMPUF(seed=secrets.token_bytes(32))
        uav_id = 2000 + i
        t, k = 4, 8

        init_c = [secrets.token_bytes(16) for _ in range(k)]
        bs.enroll_uav(uav_id, t, k, legit_puf.evaluate_set(init_c), challenges=init_c)

        attacker_uav = UAV(uav_id=uav_id, puf=attacker_puf, threshold_t=t, challenge_count_k=k)
        m1 = attacker_uav.initiate_auth()
        ok1, m2, _ = bs.process_m1(m1)
        ok2, m3, _, _ = attacker_uav.process_m2(m2)
        if ok2:
            ok3, _, _ = bs.process_m3(uav_id, m3)
            if ok3:
                far_accepts += 1

    far_pct = (far_accepts / FAR_TRIALS) * 100.0

    eval_data = {
        "timestamp": time.time(),
        "micro_benchmarks": micro_benchmarks,
        "performance_vs_security_level": perf_results,
        "communication_and_storage_costs": costs,
        "success_rate_vs_noise": success_curve,
        "false_acceptance_rate_pct": far_pct,
        "far_trials": FAR_TRIALS,
    }

    # Save JSON
    with open("results/benchmark_data.json", "w", encoding="utf-8") as f:
        json.dump(eval_data, f, indent=2)

    # Save CSV for performance vs security level
    with open("results/benchmark_data.csv", "w", encoding="utf-8") as f:
        f.write("security_level_pct,threshold_t,challenges_k,avg_time_us,min_time_us,max_time_us\n")
        for row in perf_results:
            f.write(f"{row['security_level_pct']},{row['threshold_t']},{row['challenges_k']},{row['avg_time_us']},{row['min_time_us']},{row['max_time_us']}\n")

    print("\n  [OK] Benchmark results saved to:")
    print("    - results/benchmark_data.json")
    print("    - results/benchmark_data.csv")
    print(f"  * Measured Execution Time (k=8, t=4 / 50% Sec): {perf_results[1]['avg_time_us']:.1f} µs")
    print(f"  * False Acceptance Rate (FAR): {far_pct:.4f}% ({far_accepts}/{FAR_TRIALS})")
    print("=" * 76 + "\n")


def run_web_server(port: int = 8000, open_browser: bool = True):
    """Launch Tactical Ops-Center Web Workbench via serve.py."""
    import serve
    serve.run_server(port=port)


def main():
    parser = argparse.ArgumentParser(description="UAV Swarm Authentication System")
    parser.add_argument("--sim", action="store_true", help="Run 3D PyBullet Swarm Simulation")
    parser.add_argument("--headless", action="store_true", help="Run simulation in headless mode")
    parser.add_argument("--mode", type=str, choices=["base_station", "decentralized_quorum"], default="decentralized_quorum", help="Operational protocol mode")
    parser.add_argument("--test", action="store_true", help="Run cryptographic verification test suite")
    parser.add_argument("--demo", action="store_true", help="Run step-by-step terminal walkthrough")
    parser.add_argument("--eval", action="store_true", help="Run benchmarks and save /results")
    parser.add_argument("--web", action="store_true", help="Launch Tactical Ops-Center Web Workbench")
    parser.add_argument("--port", type=int, default=8000, help="Web server port (default: 8000)")
    parser.add_argument("--t", type=int, default=3, help="Shamir threshold t")
    parser.add_argument("--k", type=int, default=6, help="Challenge count k")
    parser.add_argument("--n", type=int, default=5, help="Initial swarm size")
    args = parser.parse_args()

    if args.test:
        try:
            from tests.test_protocol import run_all_tests
        except ImportError:
            from test_protocol import run_all_tests
        run_all_tests()
    elif args.demo:
        run_demo(mode=args.mode)
    elif args.eval:
        run_evaluation()
    elif args.web:
        run_web_server(port=args.port)
    elif args.sim:
        from simulation import SwarmSimulation
        sim = SwarmSimulation(
            gui_mode=not args.headless,
            threshold_t=args.t,
            challenge_count_k=args.k,
            initial_swarm_size=args.n,
            mode=args.mode,
        )
        sim.run_loop()
    else:
        # Default: run demo and test
        run_demo(mode=args.mode)


if __name__ == "__main__":
    main()
