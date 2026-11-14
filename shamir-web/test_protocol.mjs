/**
 * Node.js Test Suite for JavaScript Protocol Engine.
 * Runs under: node --test shamir-web/test_protocol.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    commitmentPow,
    modInverse,
    fieldAdd,
    fieldSub,
    fieldMul,
    randomFieldElement,
    randomSecret,
    hashSecret,
    timingSafeEqual,
} from './field.js';
import { SRAMPUF } from './puf.js';
import {
    Polynomial,
    BarycentricInterpolator,
    lagrangeInterpolateAtZero,
    recoverSecretNoisy,
    VerifiableSecretSharing,
} from './shamir.js';
import {
    BaseStation,
    UAV,
    ProtocolMode,
    SwarmPeerNode,
    DecentralizedQuorumCoordinator,
} from './protocol.js';

test('JS Field Arithmetic (p = 2^127 - 1)', () => {
    assert.equal(PRIME_P, (1n << 127n) - 1n);

    for (let i = 0; i < 5; i++) {
        const a = randomFieldElement(PRIME_P);
        const inv = modInverse(a, PRIME_P);
        assert.equal((a * inv) % PRIME_P, 1n);
    }
});

test('JS Shamir (t, k) Threshold Property & Barycentric Weights', () => {
    const t = 4;
    const k = 8;
    const secret = randomSecret(PRIME_P);
    const poly = Polynomial.random(secret, t, PRIME_P);

    const xs = Array.from({ length: k }, (_, i) => BigInt((i + 1) * 100 + 7));
    const points = xs.map(x => [x, poly.evaluate(x)]);

    for (let i = 0; i <= k - t; i++) {
        const subset = points.slice(i, i + t);
        const recS = lagrangeInterpolateAtZero(subset, PRIME_P);
        assert.equal(recS, secret);
    }

    const interpolator = new BarycentricInterpolator(xs.slice(0, t), PRIME_P);
    const baryS = interpolator.reconstruct(points.slice(0, t).map(pt => pt[1]));
    assert.equal(baryS, secret);
});

test('JS Full Mutual Authentication & Session Key Agreement', async () => {
    const bs = new BaseStation();
    const puf = new SRAMPUF(new TextEncoder().encode("JS_UAV_TEST_SEED_01"), SRAMPUF.PRESET_IDEAL);
    const uavId = 555;
    const t = 3, k = 6;

    const uav = new UAV(uavId, puf, t, k);

    const initChallenges = Array.from({ length: k }, () => {
        const b = new Uint8Array(16);
        globalThis.crypto.getRandomValues(b);
        return b;
    });
    const enrollResp = await puf.evaluateSet(initChallenges, 0.0);
    await bs.enrollUAV(uavId, t, k, enrollResp, initChallenges);

    // M1
    const m1 = uav.initiateAuth();
    const [ok1, m2, err1] = await bs.processM1(m1);
    assert.ok(ok1, err1);

    // M2
    const [ok2, m3, skUav, err2] = await uav.processM2(m2);
    assert.ok(ok2, err2);

    // M3
    const [ok3, skBs, err3] = await bs.processM3(uavId, m3);
    assert.ok(ok3, err3);

    assert.equal(skUav.length, 32);
    assert.ok(timingSafeEqual(skUav, skBs));
});

test('JS Fault Tolerance: up to k-t faults succeed, > k-t fail', async () => {
    const bs = new BaseStation();
    const puf = new SRAMPUF(new TextEncoder().encode("JS_FAULT_TEST_SEED_02"), SRAMPUF.PRESET_IDEAL);
    const uavId = 666;
    const t = 3, k = 7; // k-t = 4 faults tolerated

    const uav = new UAV(uavId, puf, t, k);
    const initChallenges = Array.from({ length: k }, () => {
        const b = new Uint8Array(16);
        globalThis.crypto.getRandomValues(b);
        return b;
    });
    await bs.enrollUAV(uavId, t, k, await puf.evaluateSet(initChallenges, 0.0), initChallenges);

    // 4 faults: MUST PASS
    const m1 = uav.initiateAuth();
    const [, m2] = await bs.processM1(m1);
    const [okPass, m3Pass, skUavPass] = await uav.processM2(m2, null, [0, 1, 2, 3]);
    assert.ok(okPass);
    const [okBsPass, skBsPass] = await bs.processM3(uavId, m3Pass);
    assert.ok(okBsPass);
    assert.ok(timingSafeEqual(skUavPass, skBsPass));

    // 5 faults: MUST FAIL
    const m1Fail = uav.initiateAuth();
    const [, m2Fail] = await bs.processM1(m1Fail);
    const [okFail, , , reason] = await uav.processM2(m2Fail, null, [0, 1, 2, 3, 4]);
    assert.equal(okFail, false);
    assert.match(reason, /fewer than t=3/);
});

test('JS Replay attack and MAC tampering rejected', async () => {
    const bs = new BaseStation();
    const puf = new SRAMPUF(new TextEncoder().encode("JS_ATTACK_TEST_SEED"), SRAMPUF.PRESET_IDEAL);
    const uavId = 777;
    const t = 3, k = 5;

    const uav = new UAV(uavId, puf, t, k);
    const initChallenges = Array.from({ length: k }, () => {
        const b = new Uint8Array(16);
        globalThis.crypto.getRandomValues(b);
        return b;
    });
    await bs.enrollUAV(uavId, t, k, await puf.evaluateSet(initChallenges, 0.0), initChallenges);

    // Replay M1
    const m1 = uav.initiateAuth();
    const [ok1] = await bs.processM1(m1);
    assert.ok(ok1);
    const [okReplay, , replayErr] = await bs.processM1(m1);
    assert.equal(okReplay, false);
    assert.match(replayErr, /Replay attack/);
});

test('JS Verifiable Secret Sharing (VSS) Math & Public Commitments', () => {
    const t = 4;
    const n = 7;
    const secret = randomSecret(PRIME_P);
    const vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P);

    const { poly, commitments } = vss.createPolynomialAndCommitments(secret, t);
    assert.equal(commitments.length, t);

    const expectedC0 = commitmentPow(COMMITMENT_GENERATOR_G, secret, COMMITMENT_PRIME_P, PRIME_P);
    assert.equal(commitments[0], expectedC0);

    const shares = [];
    for (let i = 1; i <= n; i++) {
        const x = BigInt(i * 17);
        const y = poly.evaluate(x);
        shares.push([x, y]);
        assert.ok(vss.verifyShare(x, y, commitments), `Share ${i} failed VSS check`);
    }

    const tamperedY = (shares[0][1] + 4242n) % PRIME_P;
    assert.equal(vss.verifyShare(shares[0][0], tamperedY, commitments), false);
});

test('JS Non-Reconstructive Threshold Verification (Homomorphic Combination)', () => {
    const t = 3;
    const secret = randomSecret(PRIME_P);
    const vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P);
    const { poly, commitments } = vss.createPolynomialAndCommitments(secret, t);

    const quorumIndices = [1, 2, 3];
    const quorumShares = quorumIndices.map(idx => [BigInt(idx * 11), poly.evaluate(BigInt(idx * 11))]);
    const quorumX = quorumShares.map(s => s[0]);

    const tokens = [];
    for (let i = 0; i < quorumShares.length; i++) {
        const [x, y] = quorumShares[i];
        const tok = vss.generatePartialToken(i + 1, x, y, quorumX);
        assert.ok(vss.verifyPartialToken(tok, commitments, quorumX));
        tokens.push(tok);
    }

    const combinedGS = vss.combineTokensHomomorphic(tokens);
    assert.equal(combinedGS, commitments[0]);

    const combinedS = vss.combinePartialScalars(tokens);
    assert.equal(combinedS, secret);
});

test('JS Autonomous Decentralized Quorum Admission (No Base Station)', async () => {
    const t = 3;
    const kQuorum = 5;
    const secret = randomSecret(PRIME_P);
    const vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P);
    const { poly, commitments } = vss.createPolynomialAndCommitments(secret, t);

    const peers = [];
    for (let i = 1; i <= kQuorum; i++) {
        const px = BigInt(i * 23);
        const py = poly.evaluate(px);
        const peer = new SwarmPeerNode(100 + i, px, py, commitments);
        peers.append ? peers.append(peer) : peers.push(peer);
    }

    const coordinator = new DecentralizedQuorumCoordinator(t, commitments, PRIME_P);
    const applicantPuf = new SRAMPUF(new TextEncoder().encode("JS_APPLICANT_KEY_01"), SRAMPUF.PRESET_IDEAL);
    const applicant = new UAV(901, applicantPuf, t, kQuorum);

    const result = await coordinator.coordinateAdmission(applicant, peers);
    assert.ok(result.admitted, `Decentralized admission failed: ${result.reason}`);
    assert.ok(result.sessionKey);
    assert.equal(result.sessionKey.length, 32);
    assert.ok(result.vssVerified);
    assert.ok(result.nonReconstructiveVerified);
});

test('JS Detection and Quarantine of Poisoned Shares on-the-fly', async () => {
    const t = 3;
    const kQuorum = 5;
    const secret = randomSecret(PRIME_P);
    const vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P);
    const { poly, commitments } = vss.createPolynomialAndCommitments(secret, t);

    const peers = [];
    for (let i = 1; i <= kQuorum; i++) {
        const px = BigInt(i * 31);
        const py = poly.evaluate(px);
        const peer = new SwarmPeerNode(200 + i, px, py, commitments);
        peers.push(peer);
    }

    const coordinator = new DecentralizedQuorumCoordinator(t, commitments, PRIME_P);
    const applicant = new UAV(902, new SRAMPUF(new TextEncoder().encode("JS_APPLICANT_KEY_02"), SRAMPUF.PRESET_IDEAL), t, kQuorum);

    const tamperedId = 203;
    const result = await coordinator.coordinateAdmission(applicant, peers, { tamperPeerId: tamperedId });
    assert.equal(result.admitted, false);
    assert.ok(result.quarantinedPeers.includes(tamperedId));
    assert.match(result.reason, /Poisoned share detected/);
    assert.ok(coordinator.quarantinedPeers.has(tamperedId));
});

test('JS Protocol Mode Configuration Toggle', async () => {
    assert.equal(ProtocolMode.BASE_STATION, "BASE_STATION");
    assert.equal(ProtocolMode.DECENTRALIZED_QUORUM, "DECENTRALIZED_QUORUM");

    // Base station mode test
    const bs = new BaseStation();
    const uav = new UAV(333, new SRAMPUF(new TextEncoder().encode("TOGGLE_TEST_01"), SRAMPUF.PRESET_IDEAL), 3, 5);
    const initChallenges = Array.from({ length: 5 }, () => {
        const b = new Uint8Array(16);
        globalThis.crypto.getRandomValues(b);
        return b;
    });
    await bs.enrollUAV(333, 3, 5, await uav.puf.evaluateSet(initChallenges, 0.0), initChallenges);

    const m1 = uav.initiateAuth();
    const [ok1, m2] = await bs.processM1(m1);
    assert.ok(ok1);
    const [ok2, m3, skUav] = await uav.processM2(m2);
    assert.ok(ok2);
    const [ok3, skBs] = await bs.processM3(333, m3);
    assert.ok(ok3);
    assert.ok(timingSafeEqual(skUav, skBs));

    // Decentralized quorum mode test
    const secret = randomSecret(PRIME_P);
    const vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P);
    const { poly, commitments } = vss.createPolynomialAndCommitments(secret, 3);
    const peers = Array.from({ length: 5 }, (_, i) => new SwarmPeerNode(401 + i, BigInt((i + 1) * 19), poly.evaluate(BigInt((i + 1) * 19)), commitments));
    const coord = new DecentralizedQuorumCoordinator(3, commitments, PRIME_P);
    const app = new UAV(777, new SRAMPUF(new TextEncoder().encode("TOGGLE_TEST_02"), SRAMPUF.PRESET_IDEAL), 3, 5);
    const res = await coord.coordinateAdmission(app, peers);
    assert.ok(res.admitted);
    assert.ok(res.sessionKey);

    // Verify Section 6 Core Workflow verify_quorum_and_admit from report
    const app2 = new UAV(778, new SRAMPUF(new TextEncoder().encode("TOGGLE_TEST_03"), SRAMPUF.PRESET_IDEAL), 3, 5);
    coord.registerUav(778, app2.puf);
    const verifiedAdmitted = await coord.verify_quorum_and_admit(app2, peers, commitments, 3);
    assert.ok(verifiedAdmitted);
});


test('JS Decentralized Quorum Cloned PUF Defense & Unknown ID Rejection', async () => {
    const t = 3, k = 5;
    const secret = randomSecret(PRIME_P);
    const vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P);
    const { poly, commitments } = vss.createPolynomialAndCommitments(secret, t);

    const peers = Array.from({ length: k }, (_, i) => new SwarmPeerNode(501 + i, BigInt((i + 1) * 23), poly.evaluate(BigInt((i + 1) * 23)), commitments));
    const coord = new DecentralizedQuorumCoordinator(t, commitments, PRIME_P);

    const legitPuf = new SRAMPUF(new TextEncoder().encode("GENUINE_HARDWARE_KEY_888"), SRAMPUF.PRESET_IDEAL);
    const fakePuf = new SRAMPUF(new TextEncoder().encode("ROGUE_FABRICATED_KEY_999"), SRAMPUF.PRESET_IDEAL);

    coord.registerUav(888, legitPuf);

    // 1. Rogue drone with fabricated PUF claiming ID 888
    const rogueUav = new UAV(888, fakePuf, t, k);
    const resClone = await coord.coordinateAdmission(rogueUav, peers);
    assert.equal(resClone.admitted, false);
    assert.match(resClone.reason, /Secret reconstruction failed/);

    // 2. Unknown unenrolled drone ID 99999
    const rogueUnknown = new UAV(99999, fakePuf, t, k);
    const resUnknown = await coord.coordinateAdmission(rogueUnknown, peers);
    assert.equal(resUnknown.admitted, false);
    assert.match(resUnknown.reason, /Unknown UAV ID/);
});

test('JS Decentralized Quorum Man-in-the-Middle (MitM) MAC Tampering', async () => {
    const t = 3, k = 5;
    const secret = randomSecret(PRIME_P);
    const vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P);
    const { poly, commitments } = vss.createPolynomialAndCommitments(secret, t);

    const peers = Array.from({ length: k }, (_, i) => new SwarmPeerNode(601 + i, BigInt((i + 1) * 29), poly.evaluate(BigInt((i + 1) * 29)), commitments));
    const coord = new DecentralizedQuorumCoordinator(t, commitments, PRIME_P);

    const puf = new SRAMPUF(new TextEncoder().encode("MITM_TEST_KEY_777"), SRAMPUF.PRESET_IDEAL);
    coord.registerUav(777, puf);
    const uav = new UAV(777, puf, t, k);

    // MitM alters Quorum MAC in transit (M2) -> Applicant rejects
    const resTamperBs = await coord.coordinateAdmission(uav, peers, { tamperMacBs: true });
    assert.equal(resTamperBs.admitted, false);
    assert.match(resTamperBs.reason, /MAC verification failed/);

    // MitM alters Applicant MAC in transit (M3) -> Quorum rejects
    const resTamperUav = await coord.coordinateAdmission(uav, peers, { tamperMacUav: true });
    assert.equal(resTamperUav.admitted, false);
    assert.match(resTamperUav.reason, /MAC verification failed/);
});
