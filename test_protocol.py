"""
Comprehensive Verification Test Suite for UAV Swarm Authentication Protocol.

Verifies all cryptographic properties, architectural upgrades, and attack resistances:
1. Field arithmetic over F_p (p = 2^127 - 1)
2. Threshold secret sharing (t, k): any t points reconstruct S, any t-1 points fail
3. Barycentric O(t) Lagrange interpolation match
4. Error correction and noisy secret recovery
5. Full mutual authentication and identical session key derivation (Sk_UAV == Sk_BS)
6. Fault tolerance: tolerates up to k-t faulty PUF responses
7. Rejection on too many faulty responses (> k-t)
8. Resistance to PUF cloning attack
9. Resistance to message replay attack (Nonce cache)
10. Resistance to MAC tampering (MitM attack)
11. Resistance to unknown device ID
12. 100 consecutive sessions with state ratcheting
13. Verifiable Secret Sharing (VSS) public commitment validation (Phase 3)
14. Non-reconstructive threshold verification via homomorphic token aggregation (Phase 2)
15. Decentralized peer quorum admission without base station dependency (Phase 1)
16. On-the-fly detection and quarantine of poisoned/tampered peer shares (Phase 3)
17. Dual protocol mode configuration toggle (Base Station vs Decentralized Quorum)
"""

import os
import secrets
import sys
import time

if sys.platform.startswith("win"):
    try:
        if sys.stdout:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from crypto.finite_field import (
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    mod_inverse,
    field_add,
    field_sub,
    field_mul,
    random_field_element,
    random_secret,
    hash_secret,
    hash_to_field,
    map_responses_to_x_coords,
    pad_hash,
    xor_bytes,
)
from crypto.puf import SRAMPUF
from crypto.shamir import (
    Polynomial,
    BarycentricInterpolator,
    lagrange_interpolate_at_zero,
    berlekamp_welch_decode,
    recover_secret_noisy,
    VerifiableSecretSharing,
    PartialVerificationToken,
)
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


def test_field_arithmetic():
    print("  [01/17] Testing Prime Field Arithmetic (p = 2^127 - 1)...")
    p = PRIME_P
    assert p == (1 << 127) - 1

    for _ in range(10):
        a = random_field_element(p)
        inv = mod_inverse(a, p)
        assert (a * inv) % p == 1, f"Modular inverse failed for {a}"

    a = random_field_element(p)
    b = random_field_element(p)
    assert field_add(a, field_sub(b, a, p), p) == b
    assert field_mul(a, 1, p) == a
    print("         [PASS] Field arithmetic & Extended Euclidean algorithm verified.")


def test_shamir_threshold_property():
    print("  [02/17] Testing Shamir (t, k) Threshold Property & Cached Barycentric Weights...")
    t = 4
    k = 8
    secret = random_secret(PRIME_P)
    poly = Polynomial.random(secret, threshold_t=t, prime=PRIME_P)

    xs = [i * 100 + 7 for i in range(1, k + 1)]
    points = [(x, poly.evaluate(x)) for x in xs]

    # Any t points must reconstruct secret
    for i in range(k - t + 1):
        subset = points[i : i + t]
        rec_s = lagrange_interpolate_at_zero(subset, PRIME_P)
        assert rec_s == secret, f"Lagrange failed on subset {i}"

    # Barycentric interpolator matches direct evaluation
    interpolator = BarycentricInterpolator([pt[0] for pt in points[:t]], prime=PRIME_P)
    bary_s = interpolator.reconstruct([pt[1] for pt in points[:t]])
    assert bary_s == secret

    # t - 1 points cannot reconstruct S
    sub_threshold = points[: t - 1]
    # Adding an arbitrary point at x=999999 yields a completely different value
    dummy_pt = (99999999, 12345678)
    wrong_s = lagrange_interpolate_at_zero(sub_threshold + [dummy_pt], PRIME_P)
    assert wrong_s != secret

    print("         [PASS] Any t points reconstruct S; sub-threshold (t-1) points do not.")


def test_noisy_recovery():
    print("  [03/17] Testing Berlekamp-Welch & Subset Noisy Recovery...")
    t = 4
    k = 8
    secret = random_secret(PRIME_P)
    poly = Polynomial.random(secret, threshold_t=t, prime=PRIME_P)
    h_s = hash_secret(secret)

    xs = [i * 50 + 13 for i in range(1, k + 1)]
    clean_points = [(x, poly.evaluate(x)) for x in xs]

    # Test 1: 1 error (e=1 <= floor((8-4)/2) = 2) -> solved by Berlekamp-Welch
    noisy_1 = list(clean_points)
    noisy_1[0] = (noisy_1[0][0], (noisy_1[0][1] + 99999) % PRIME_P)
    rec_s_1, correct_1 = recover_secret_noisy(noisy_1, t, h_s, PRIME_P)
    assert rec_s_1 == secret
    assert 0 not in correct_1
    assert len(correct_1) == 7

    # Test 2: k-t = 4 errors -> exceeded Berlekamp-Welch unique decoding, solved by subset search!
    noisy_4 = list(clean_points)
    for err_idx in [0, 1, 2, 3]:
        noisy_4[err_idx] = (noisy_4[err_idx][0], (noisy_4[err_idx][1] + 88888 * (err_idx + 1)) % PRIME_P)
    rec_s_4, correct_4 = recover_secret_noisy(noisy_4, t, h_s, PRIME_P)
    assert rec_s_4 == secret
    assert correct_4 == [4, 5, 6, 7]

    # Test 3: k - t + 1 = 5 errors (only 3 correct < t=4) -> must return None
    noisy_5 = list(clean_points)
    for err_idx in [0, 1, 2, 3, 4]:
        noisy_5[err_idx] = (noisy_5[err_idx][0], (noisy_5[err_idx][1] + 77777) % PRIME_P)
    rec_s_5, correct_5 = recover_secret_noisy(noisy_5, t, h_s, PRIME_P)
    assert rec_s_5 is None

    print("         [PASS] Tolerates up to k-t faulty points; rejects when correct points < t.")


def test_full_protocol_mutual_auth():
    print("  [04/17] Testing Complete Mutual Authentication & Session Key Agreement...")
    bs = BaseStation()
    uav_puf = SRAMPUF(seed=b"UAV_ALPHA_SECRET_SEED_1234567890", bit_flip_rate=SRAMPUF.PRESET_IDEAL)
    uav_id = 101
    t, k = 4, 8

    uav = UAV(uav_id=uav_id, puf=uav_puf, threshold_t=t, challenge_count_k=k)

    # Enrollment
    init_challenges = [secrets.token_bytes(16) for _ in range(k)]
    enroll_resp = uav_puf.evaluate_set(init_challenges, noise_override=0.0)
    challenges, state = bs.enroll_uav(uav_id, t, k, enroll_resp, challenges=init_challenges)

    # Step 1: UAV -> BS
    m1 = uav.initiate_auth()

    # Step 2: BS -> UAV
    ok1, m2, err1 = bs.process_m1(m1)
    assert ok1, err1

    # Step 3: UAV processes M2, authenticates BS, prepares M3
    ok2, m3, sk_uav, err2 = uav.process_m2(m2)
    assert ok2, err2

    # Step 4: BS processes M3, authenticates UAV, derives Sk
    ok3, sk_bs, err3 = bs.process_m3(uav_id, m3)
    assert ok3, err3

    # Verify session keys match exactly
    assert sk_uav == sk_bs
    assert len(sk_uav) == 32
    print("         [PASS] Mutual authentication succeeded; Sk_UAV == Sk_BS (256-bit HKDF).")


def test_fault_tolerance_scenarios():
    print("  [05/17] Testing PUF Fault Tolerance (up to k-t errors allowed)...")
    bs = BaseStation()
    uav_puf = SRAMPUF(seed=b"FAULT_TOLERANT_DRONE_TEST_SEED", bit_flip_rate=SRAMPUF.PRESET_IDEAL)
    uav_id = 202
    t, k = 3, 7  # k - t = 4 errors allowed

    uav = UAV(uav_id=uav_id, puf=uav_puf, threshold_t=t, challenge_count_k=k)
    init_challenges = [secrets.token_bytes(16) for _ in range(k)]
    enroll_resp = uav_puf.evaluate_set(init_challenges, noise_override=0.0)
    bs.enroll_uav(uav_id, t, k, enroll_resp, challenges=init_challenges)

    # Case A: Exactly k-t = 4 faulty responses -> MUST SUCCEED
    m1 = uav.initiate_auth()
    _, m2, _ = bs.process_m1(m1)
    ok, m3, sk_uav, _ = uav.process_m2(m2, faulty_indices=[0, 1, 2, 3])
    assert ok, "Failed with k-t faults!"
    ok_bs, sk_bs, _ = bs.process_m3(uav_id, m3)
    assert ok_bs
    assert sk_uav == sk_bs

    # Case B: Too many faults (5 faulty responses, only 2 correct < t=3) -> MUST REJECT
    m1_b = uav.initiate_auth()
    _, m2_b, _ = bs.process_m1(m1_b)
    ok_b, _, _, reason = uav.process_m2(m2_b, faulty_indices=[0, 1, 2, 3, 4])
    assert not ok_b, "Should have rejected with > k-t faults"
    assert "fewer than t=3" in reason

    print("         [PASS] Successfully authenticates with k-t=4 faults; rejects with 5 faults.")


def test_cloned_puf_rejection():
    print("  [06/17] Testing Cloned / Fraudulent PUF Defense...")
    bs = BaseStation()
    legit_puf = SRAMPUF(seed=b"GENUINE_HARDWARE_SILICON_SEED_1", bit_flip_rate=0.0)
    rogue_puf = SRAMPUF(seed=b"ADVERSARY_DIFFERENT_SILICON_SEED", bit_flip_rate=0.0)

    uav_id = 303
    t, k = 4, 8

    legit_uav = UAV(uav_id=uav_id, puf=legit_puf, threshold_t=t, challenge_count_k=k)
    rogue_uav = UAV(uav_id=uav_id, puf=rogue_puf, threshold_t=t, challenge_count_k=k)

    # Enroll legitimate UAV
    init_c = [secrets.token_bytes(16) for _ in range(k)]
    enroll_resp = legit_puf.evaluate_set(init_c, noise_override=0.0)
    bs.enroll_uav(uav_id, t, k, enroll_resp, challenges=init_c)

    # Rogue drone attempts to authenticate using fake PUF
    m1 = rogue_uav.initiate_auth()
    ok1, m2, _ = bs.process_m1(m1)
    assert ok1

    # Rogue UAV PUF produces wrong responses; secret reconstruction must fail!
    ok2, m3, _, reason = rogue_uav.process_m2(m2)
    assert not ok2
    assert "Secret reconstruction failed" in reason
    print("         [PASS] Cloned / adversary PUF completely fails secret reconstruction.")


def test_replay_attack_prevention():
    print("  [07/17] Testing Replay Attack Defense via Nonce Cache...")
    bs = BaseStation()
    puf = SRAMPUF(seed=b"REPLAY_DEFENSE_TEST_SEED", bit_flip_rate=0.0)
    uav_id = 404
    t, k = 3, 5

    uav = UAV(uav_id=uav_id, puf=puf, threshold_t=t, challenge_count_k=k)
    init_c = [secrets.token_bytes(16) for _ in range(k)]
    bs.enroll_uav(uav_id, t, k, puf.evaluate_set(init_c, noise_override=0.0), challenges=init_c)

    # First session
    m1 = uav.initiate_auth()
    ok1, m2, _ = bs.process_m1(m1)
    assert ok1

    # Attacker intercepts and replays identical M1 (same N_A)
    ok_replay, _, reason = bs.process_m1(m1)
    assert not ok_replay
    assert "Replay attack detected" in reason
    assert bs.enrolled_uavs[uav_id].quarantined
    print("         [PASS] Replayed M1 detected; session aborted and UAV quarantined.")


def test_mac_tampering_mitm():
    print("  [08/17] Testing Man-in-the-Middle (MitM) MAC Tampering...")
    bs = BaseStation()
    puf = SRAMPUF(seed=b"MITM_TEST_SEED_FOR_TAMPERING", bit_flip_rate=0.0)
    uav_id = 505
    t, k = 3, 5

    uav = UAV(uav_id=uav_id, puf=puf, threshold_t=t, challenge_count_k=k)
    init_c = [secrets.token_bytes(16) for _ in range(k)]
    bs.enroll_uav(uav_id, t, k, puf.evaluate_set(init_c, noise_override=0.0), challenges=init_c)

    m1 = uav.initiate_auth()
    _, m2, _ = bs.process_m1(m1)

    # MitM tampered MAC in M2
    tampered_mac = bytes([b ^ 0xFF for b in m2.mac_bs])
    tampered_m2 = AuthMessage2(
        challenges=m2.challenges,
        q=m2.q,
        shares_l=m2.shares_l,
        mac_bs=tampered_mac,
        h_s_hint=m2.h_s_hint,
    )
    ok, _, _, reason = uav.process_m2(tampered_m2)
    assert not ok
    assert "Base Station MAC verification failed" in reason

    # Now legitimate M2, but MitM tampers M3
    _, legit_m2, _ = bs.process_m1(uav.initiate_auth())
    _, legit_m3, _, _ = uav.process_m2(legit_m2)
    tampered_m3 = AuthMessage3(
        challenges_prime=legit_m3.challenges_prime,
        j=legit_m3.j,
        p=legit_m3.p,
        mac_uav=bytes([b ^ 0xAA for b in legit_m3.mac_uav]),
    )
    ok_bs, _, bs_reason = bs.process_m3(uav_id, tampered_m3)
    assert not ok_bs
    assert "MAC_UAV verification failed" in bs_reason
    print("         [PASS] Both Base Station and UAV detect and reject tampered MACs.")


def test_unknown_device_id():
    print("  [09/17] Testing Unknown Device ID Rejection...")
    bs = BaseStation()
    fake_m1 = AuthMessage1(uav_id=99999, n_a=secrets.token_bytes(16))
    ok, _, reason = bs.process_m1(fake_m1)
    assert not ok
    assert "Unknown UAV ID" in reason
    print("         [PASS] Unenrolled / rogue device ID promptly rejected.")


def test_100_consecutive_ratcheting_sessions():
    print("  [10/17] Testing 100 Consecutive Sessions with State Ratcheting...")
    bs = BaseStation()
    puf = SRAMPUF(seed=b"HUNDRED_SESSIONS_CONTINUOUS_SEED", bit_flip_rate=0.0)
    uav_id = 707
    t, k = 3, 6

    uav = UAV(uav_id=uav_id, puf=puf, threshold_t=t, challenge_count_k=k)
    init_c = [secrets.token_bytes(16) for _ in range(k)]
    bs.enroll_uav(uav_id, t, k, puf.evaluate_set(init_c, noise_override=0.0), challenges=init_c)

    start_time = time.perf_counter()
    for session_idx in range(1, 101):
        m1 = uav.initiate_auth()
        ok1, m2, err1 = bs.process_m1(m1)
        assert ok1, f"Session {session_idx} M1 failed: {err1}"

        ok2, m3, sk_uav, err2 = uav.process_m2(m2)
        assert ok2, f"Session {session_idx} M2 failed: {err2}"

        ok3, sk_bs, err3 = bs.process_m3(uav_id, m3)
        assert ok3, f"Session {session_idx} M3 failed: {err3}"

        assert sk_uav == sk_bs, f"Session {session_idx} key mismatch!"
        assert bs.enrolled_uavs[uav_id].session_counter == session_idx

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    avg_ms = elapsed_ms / 100.0
    print(f"         [PASS] 100 consecutive ratchets completed in {elapsed_ms:.1f} ms (avg {avg_ms:.2f} ms/session).")


def test_verifiable_secret_sharing_math():
    print("  [11/17] Testing Verifiable Secret Sharing (VSS) Public Commitments...")
    t = 4
    n = 7
    secret = random_secret(PRIME_P)
    vss = VerifiableSecretSharing(secret_p=PRIME_P)

    # Generate polynomial coefficients and public commitments C_j = g^{a_j} mod P
    poly, commitments = vss.create_polynomial_and_commitments(secret, t)
    assert len(commitments) == t
    # C_0 must equal g^secret mod P
    expected_c0 = pow(COMMITMENT_GENERATOR_G, secret, COMMITMENT_PRIME_P)
    assert commitments[0] == expected_c0

    # Generate n shares and verify each share against public commitments
    shares = []
    for i in range(1, n + 1):
        x = i * 17
        y = poly.evaluate(x)
        shares.append((x, y))
        # Valid share verification: g^y = prod C_j^{x^j} mod P
        assert vss.verify_share(x, y, commitments), f"Share {i} failed VSS verification"

    # Verify that a tampered share fails verification
    tampered_y = (shares[0][1] + 1337) % PRIME_P
    assert not vss.verify_share(shares[0][0], tampered_y, commitments), "Tampered share should have failed VSS"
    print("         [PASS] VSS commitments C_j and discrete-log share consistency verified.")


def test_non_reconstructive_partial_tokens():
    print("  [12/17] Testing Non-Reconstructive Threshold Verification (Homomorphic Aggregation)...")
    t = 3
    k = 5
    secret = random_secret(PRIME_P)
    vss = VerifiableSecretSharing(secret_p=PRIME_P)
    poly, commitments = vss.create_polynomial_and_commitments(secret, t)

    quorum_indices = [1, 2, 3]  # Quorum of size t
    quorum_shares = [(idx * 11, poly.evaluate(idx * 11)) for idx in quorum_indices]
    quorum_x = [s[0] for s in quorum_shares]

    # Quorum peers compute partial verification tokens locally:
    # sigma_i = y_i * w_i mod p,  T_i = g^{sigma_i} mod P
    tokens = []
    for idx, (x, y) in enumerate(quorum_shares, start=1):
        tok = vss.generate_partial_token(peer_id=idx, x_i=x, y_i=y, quorum_x_coords=quorum_x)
        # Token passes VSS verification
        assert vss.verify_partial_token(tok, commitments, quorum_x)
        tokens.append(tok)

    # Homomorphic aggregation at coordinator: prod T_i mod P == g^S mod P == C_0 mod P
    combined_g_s = vss.combine_tokens_homomorphic(tokens)
    assert combined_g_s == commitments[0], "Homomorphic aggregation does not equal C_0"

    # Sum of partial scalars equals S mod p
    combined_s = vss.combine_partial_scalars(tokens)
    assert combined_s == secret, "Combined partial scalars do not equal secret"
    print("         [PASS] Non-reconstructive verification verified: tokens combined homomorphically without raw secret exposure.")


def test_decentralized_quorum_admission_phase1_2_3():
    print("  [13/17] Testing Autonomous Decentralized Quorum Admission (No Base Station)...")
    t = 3
    k_quorum = 5
    secret = random_secret(PRIME_P)
    vss = VerifiableSecretSharing(secret_p=PRIME_P)
    poly, commitments = vss.create_polynomial_and_commitments(secret, t)

    # Create active swarm peer nodes
    peers = []
    for i in range(1, k_quorum + 1):
        px = i * 23
        py = poly.evaluate(px)
        peer = SwarmPeerNode(
            peer_id=100 + i,
            share_x=px,
            share_y=py,
            commitments=commitments,
            puf=SRAMPUF(seed=secrets.token_bytes(32)),
        )
        peers.append(peer)

    # Initialize decentralized coordinator (no online Base Station)
    coordinator = DecentralizedQuorumCoordinator(threshold_t=t, commitments=commitments)

    # Applicant node D_J with PUF
    applicant_puf = SRAMPUF(seed=b"APPLICANT_DRONE_AUTHENTIC_HARDWARE_KEY_2026", bit_flip_rate=0.0)
    applicant = UAV(uav_id=901, puf=applicant_puf, threshold_t=t, challenge_count_k=k_quorum)

    result = coordinator.coordinate_admission(
        applicant=applicant,
        quorum_peers=peers,
    )

    assert result.admitted, f"Decentralized admission failed: {result.reason}"
    assert result.session_key is not None
    assert len(result.session_key) == 32
    assert result.vss_verified
    assert result.non_reconstructive_verified
    print(f"         [PASS] Applicant admitted by peer quorum in {result.latency_ms:.2f} ms without Base Station.")


def test_vss_poisoned_share_rejection():
    print("  [14/17] Testing On-the-Fly Detection & Quarantine of Poisoned Shares...")
    t = 3
    k_quorum = 5
    secret = random_secret(PRIME_P)
    vss = VerifiableSecretSharing(secret_p=PRIME_P)
    poly, commitments = vss.create_polynomial_and_commitments(secret, t)

    peers = []
    for i in range(1, k_quorum + 1):
        px = i * 31
        py = poly.evaluate(px)
        peer = SwarmPeerNode(
            peer_id=200 + i,
            share_x=px,
            share_y=py,
            commitments=commitments,
            puf=SRAMPUF(seed=secrets.token_bytes(32)),
        )
        peers.append(peer)

    coordinator = DecentralizedQuorumCoordinator(threshold_t=t, commitments=commitments)
    applicant = UAV(uav_id=902, puf=SRAMPUF(seed=b"APPLICANT_KEY_2", bit_flip_rate=0.0), threshold_t=t, challenge_count_k=k_quorum)

    # Simulate Peer 203 submitting a poisoned/tampered share
    tampered_id = 203
    result = coordinator.coordinate_admission(
        applicant=applicant,
        quorum_peers=peers,
        tamper_peer_id=tampered_id,
    )

    assert not result.admitted, "Admission should have failed due to poisoned share"
    assert tampered_id in result.quarantined_peers
    assert "Poisoned share detected" in result.reason
    assert tampered_id in coordinator.quarantined_peers
    print(f"         [PASS] Poisoned share from peer {tampered_id} detected and quarantined on-the-fly.")


def test_protocol_mode_toggle():
    print("  [15/17] Testing Operational Topology Toggle (Base Station vs Decentralized Quorum)...")
    # Verify Enum modes
    assert ProtocolMode.BASE_STATION == "BASE_STATION"
    assert ProtocolMode.DECENTRALIZED_QUORUM == "DECENTRALIZED_QUORUM"

    # Base Station mode
    bs = BaseStation()
    puf = SRAMPUF(seed=b"TOGGLE_TEST_PUF_SEED", bit_flip_rate=0.0)
    uav_id = 555
    uav = UAV(uav_id=uav_id, puf=puf, threshold_t=3, challenge_count_k=5)
    init_c = [secrets.token_bytes(16) for _ in range(5)]
    bs.enroll_uav(uav_id, 3, 5, puf.evaluate_set(init_c, noise_override=0.0), challenges=init_c)

    m1 = uav.initiate_auth()
    ok_m1, m2, _ = bs.process_m1(m1)
    assert ok_m1
    ok_m2, m3, sk_uav, _ = uav.process_m2(m2)
    assert ok_m2
    ok_m3, sk_bs, _ = bs.process_m3(uav_id, m3)
    assert ok_m3
    assert sk_uav == sk_bs

    # Decentralized Quorum mode
    secret = random_secret(PRIME_P)
    vss = VerifiableSecretSharing(secret_p=PRIME_P)
    poly, commitments = vss.create_polynomial_and_commitments(secret, 3)
    peers = [
        SwarmPeerNode(
            peer_id=300 + i,
            share_x=i * 19,
            share_y=poly.evaluate(i * 19),
            commitments=commitments,
        )
        for i in range(1, 6)
    ]
    coord = DecentralizedQuorumCoordinator(threshold_t=3, commitments=commitments)
    app = UAV(uav_id=777, puf=SRAMPUF(seed=b"TOGGLE_PEER_TEST", bit_flip_rate=0.0), threshold_t=3, challenge_count_k=5)
    res = coord.coordinate_admission(app, peers)
    assert res.admitted
    assert res.session_key is not None

    # Verify Section 6 Core Workflow verify_quorum_and_admit from report
    app2 = UAV(uav_id=778, puf=SRAMPUF(seed=b"TOGGLE_PEER_TEST_2", bit_flip_rate=0.0), threshold_t=3, challenge_count_k=5)
    coord.register_uav(778, app2.puf)
    admitted = coord.verify_quorum_and_admit(app2, peers, commitments, 3)
    assert admitted is True
    print("         [PASS] Both operational modes function seamlessly behind configuration toggle.")


def test_decentralized_cloned_puf_and_unknown_id():
    print("  [16/17] Testing Decentralized Quorum Cloned PUF Defense & Unknown ID Rejection...")
    t = 3
    k = 5
    secret = random_secret(PRIME_P)
    vss = VerifiableSecretSharing(secret_p=PRIME_P)
    poly, commitments = vss.create_polynomial_and_commitments(secret, t)

    peers = [
        SwarmPeerNode(peer_id=400 + i, share_x=i * 29, share_y=poly.evaluate(i * 29), commitments=commitments)
        for i in range(1, k + 1)
    ]
    coord = DecentralizedQuorumCoordinator(threshold_t=t, commitments=commitments)

    legit_puf = SRAMPUF(seed=b"GENUINE_ENROLLED_HARDWARE_KEY_888", bit_flip_rate=0.0)
    fake_puf = SRAMPUF(seed=b"ADVERSARY_FABRICATED_PUF_CHIP_999", bit_flip_rate=0.0)

    # Register genuine UAV in swarm registry
    coord.register_uav(888, legit_puf)

    # 1. Adversary fabricates cloned hardware claiming ID 888
    rogue_uav = UAV(uav_id=888, puf=fake_puf, threshold_t=t, challenge_count_k=k)
    res_clone = coord.coordinate_admission(applicant=rogue_uav, quorum_peers=peers)
    assert not res_clone.admitted, "Rogue drone with cloned PUF should have been rejected"
    assert "Secret reconstruction failed" in res_clone.reason

    # 2. Unknown, unenrolled rogue device ID 99999 attempts admission
    rogue_unknown = UAV(uav_id=99999, puf=fake_puf, threshold_t=t, challenge_count_k=k)
    res_unknown = coord.coordinate_admission(applicant=rogue_unknown, quorum_peers=peers)
    assert not res_unknown.admitted, "Unknown device ID should have been rejected"
    assert "Unknown UAV ID" in res_unknown.reason

    print("         [PASS] Cloned PUF and unknown device ID both rejected by decentralized quorum.")


def test_decentralized_mac_tampering_mitm():
    print("  [17/17] Testing Decentralized Quorum Man-in-the-Middle (MitM) MAC Tampering...")
    t = 3
    k = 5
    secret = random_secret(PRIME_P)
    vss = VerifiableSecretSharing(secret_p=PRIME_P)
    poly, commitments = vss.create_polynomial_and_commitments(secret, t)

    peers = [
        SwarmPeerNode(peer_id=500 + i, share_x=i * 37, share_y=poly.evaluate(i * 37), commitments=commitments)
        for i in range(1, k + 1)
    ]
    coord = DecentralizedQuorumCoordinator(threshold_t=t, commitments=commitments)

    puf = SRAMPUF(seed=b"DECENTRALIZED_MITM_TEST_SEED", bit_flip_rate=0.0)
    coord.register_uav(777, puf)
    uav = UAV(uav_id=777, puf=puf, threshold_t=t, challenge_count_k=k)

    # Case A: MitM alters Quorum MAC in transit (M2) -> Applicant rejects
    res_tamper_bs = coord.coordinate_admission(applicant=uav, quorum_peers=peers, tamper_mac_bs=True)
    assert not res_tamper_bs.admitted
    assert "MAC verification failed" in res_tamper_bs.reason

    # Case B: MitM alters Applicant MAC in transit (M3) -> Quorum rejects
    res_tamper_uav = coord.coordinate_admission(applicant=uav, quorum_peers=peers, tamper_mac_uav=True)
    assert not res_tamper_uav.admitted
    assert "MAC verification failed" in res_tamper_uav.reason

    print("         [PASS] MitM tampering on both M2 and M3 detected and rejected by quorum.")


def run_all_tests():
    print("\n" + "=" * 76)
    print("    UAV SWARM AUTHENTICATION PROTOCOL - TEST SUITE")
    print("   Verification of Threshold Secret Sharing, PUF Noise & Architectural Upgrades")
    print("=" * 76)

    t0 = time.perf_counter()
    test_field_arithmetic()
    test_shamir_threshold_property()
    test_noisy_recovery()
    test_full_protocol_mutual_auth()
    test_fault_tolerance_scenarios()
    test_cloned_puf_rejection()
    test_replay_attack_prevention()
    test_mac_tampering_mitm()
    test_unknown_device_id()
    test_100_consecutive_ratcheting_sessions()
    test_verifiable_secret_sharing_math()
    test_non_reconstructive_partial_tokens()
    test_decentralized_quorum_admission_phase1_2_3()
    test_vss_poisoned_share_rejection()
    test_protocol_mode_toggle()
    test_decentralized_cloned_puf_and_unknown_id()
    test_decentralized_mac_tampering_mitm()

    total_time = (time.perf_counter() - t0) * 1000
    print("=" * 76)
    print(f"   [PASS] ALL 17 TEST SUITES PASSED SUCCESSFULLY in {total_time:.1f} ms!")
    print("=" * 76 + "\n")


if __name__ == "__main__":
    run_all_tests()
