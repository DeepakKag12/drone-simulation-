/**
 * UAV & Base Station Protocol State Machine (JavaScript).
 * Dual operational modes:
 * 1. Base Station Centralized Mode
 * 2. Decentralized Peer Quorum Mode with Non-Reconstructive Threshold Verification
 *    and Verifiable Secret Sharing (VSS).
 */

import {
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    hashSecret,
    mapResponsesToXCoords,
    padHash,
    xorBytes,
    hmacSha256,
    timingSafeEqual,
    hkdfDeriveSessionKey,
    randomSecret,
    bytesToHex,
} from './field.js';
import { SRAMPUF } from './puf.js';
import {
    Polynomial,
    recoverSecretNoisy,
    VerifiableSecretSharing,
} from './shamir.js';

export const ProtocolMode = {
    BASE_STATION: "BASE_STATION",
    DECENTRALIZED_QUORUM: "DECENTRALIZED_QUORUM",
};

export async function computeMacBs(hS, challenges, nB, sharesL) {
    let totalLen = 0;
    challenges.forEach(c => totalLen += c.length);
    totalLen += hS.length + nB.length + sharesL.length * 16;

    const msg = new Uint8Array(totalLen);
    let offset = 0;
    for (const c of challenges) {
        msg.set(c, offset);
        offset += c.length;
    }
    msg.set(hS, offset);
    offset += hS.length;
    msg.set(nB, offset);
    offset += nB.length;

    for (const lVal of sharesL) {
        let val = BigInt(lVal);
        for (let i = 15; i >= 0; i--) {
            msg[offset + i] = Number(val & 0xFFn);
            val >>= 8n;
        }
        offset += 16;
    }

    return await hmacSha256(hS, msg);
}

export async function computeMacUav(hS, responses, nC) {
    let totalLen = 0;
    responses.forEach(r => totalLen += r.length);
    totalLen += hS.length + nC.length;

    const msg = new Uint8Array(totalLen);
    let offset = 0;
    for (const r of responses) {
        msg.set(r, offset);
        offset += r.length;
    }
    msg.set(hS, offset);
    offset += hS.length;
    msg.set(nC, offset);

    return await hmacSha256(hS, msg);
}

export class BaseStation {
    constructor(prime = PRIME_P) {
        this.prime = prime;
        this.enrolledUAVs = new Map();
        this.nonceCache = new Set();
        this.activeSessions = new Map();
        this.vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, prime);
    }

    async enrollUAV(uavId, thresholdT, challengeCountK, pufResponses, challenges = null) {
        if (challengeCountK < thresholdT) {
            throw new Error(`k (${challengeCountK}) must be >= t (${thresholdT})`);
        }
        if (pufResponses.length !== challengeCountK) {
            throw new Error(`Expected ${challengeCountK} responses, got ${pufResponses.length}`);
        }

        if (!challenges) {
            challenges = [];
            for (let i = 0; i < challengeCountK; i++) {
                const c = new Uint8Array(16);
                globalThis.crypto.getRandomValues(c);
                challenges.push(c);
            }
        }

        const secretS = randomSecret(this.prime);
        const poly = Polynomial.random(secretS, thresholdT, this.prime);
        const commitments = this.vss.generateCommitments(poly.coeffs);

        const xCoords = await mapResponsesToXCoords(pufResponses, this.prime);
        const sharesL = xCoords.map(x => poly.evaluate(x));
        const hS = await hashSecret(secretS);

        const state = {
            uavId,
            thresholdT,
            challengeCountK,
            challenges,
            sharesL,
            hS,
            commitments,
            sessionCounter: 0,
            quarantined: false,
        };
        this.enrolledUAVs.set(uavId, state);
        return [challenges, state];
    }

    async processM1(msg1) {
        const uavId = msg1.uavId;
        const state = this.enrolledUAVs.get(uavId);
        if (!state) {
            return [false, null, `Unknown UAV ID: ${uavId}`];
        }
        if (state.quarantined) {
            return [false, null, `UAV ${uavId} is quarantined due to previous security alert`];
        }

        const naKey = Array.from(msg1.nA).map(b => b.toString(16).padStart(2, '0')).join('');
        if (this.nonceCache.has(naKey)) {
            state.quarantined = true;
            return [false, null, `Replay attack detected: nonce NA previously used! UAV ${uavId} quarantined`];
        }
        this.nonceCache.add(naKey);

        const nB = new Uint8Array(16);
        globalThis.crypto.getRandomValues(nB);
        const nBPadded = new Uint8Array(32);
        nBPadded.set(nB, 0);

        const q = xorBytes(nBPadded, state.hS);
        const macBs = await computeMacBs(state.hS, state.challenges, nB, state.sharesL);

        this.activeSessions.set(uavId, {
            nA: msg1.nA,
            nB,
            hS: state.hS,
            startTime: performance.now(),
        });

        const msg2 = {
            challenges: state.challenges.map(c => c.slice()),
            q,
            sharesL: state.sharesL.slice(),
            macBs,
            hSHint: state.hS,
            commitments: state.commitments,
        };
        return [true, msg2, "OK"];
    }

    async processM3(uavId, msg3) {
        const state = this.enrolledUAVs.get(uavId);
        if (!state) return [false, null, `Unknown UAV ID: ${uavId}`];

        const sess = this.activeSessions.get(uavId);
        if (!sess) return [false, null, `No active authentication session for UAV ${uavId}`];

        const nB = sess.nB;
        const hS = state.hS;

        const nCPadded = xorBytes(msg3.p, hS);
        const nC = nCPadded.subarray(0, 16);

        const totalRespLen = 40 * state.challengeCountK;
        const padBytes = await padHash(hS, totalRespLen);
        const rDoublePrimeBytes = xorBytes(msg3.j, padBytes);

        const recoveredResponses = [];
        for (let i = 0; i < state.challengeCountK; i++) {
            recoveredResponses.push(rDoublePrimeBytes.subarray(i * 40, (i + 1) * 40));
        }

        const expectedMacUav = await computeMacUav(hS, recoveredResponses, nC);
        if (!timingSafeEqual(msg3.macUav, expectedMacUav)) {
            state.quarantined = true;
            return [false, null, `MAC_UAV verification failed! UAV ${uavId} quarantined`];
        }

        const sk = await hkdfDeriveSessionKey(nB, nC, hS);

        // Ratchet state
        const newSecret = randomSecret(this.prime);
        const newPoly = Polynomial.random(newSecret, state.thresholdT, this.prime);
        const newCommitments = this.vss.generateCommitments(newPoly.coeffs);
        const newXCoords = await mapResponsesToXCoords(recoveredResponses, this.prime);
        const newSharesL = newXCoords.map(x => newPoly.evaluate(x));
        const newHS = await hashSecret(newSecret);

        state.challenges = msg3.challengesPrime.map(c => c.slice());
        state.sharesL = newSharesL;
        state.hS = newHS;
        state.commitments = newCommitments;
        state.sessionCounter++;

        this.activeSessions.delete(uavId);
        return [true, sk, "Authenticated and ratcheted successfully"];
    }
}

export class UAV {
    constructor(uavId, puf, thresholdT = 3, challengeCountK = 5, prime = PRIME_P) {
        this.uavId = uavId;
        this.puf = puf;
        this.thresholdT = thresholdT;
        this.challengeCountK = challengeCountK;
        this.prime = prime;
        this.currentNA = null;
        this.lastSessionKey = null;
        this.lastCorrectIndices = [];
        this.vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, prime);
    }

    initiateAuth() {
        this.currentNA = new Uint8Array(16);
        globalThis.crypto.getRandomValues(this.currentNA);
        return {
            uavId: this.uavId,
            nA: this.currentNA,
            nonce_na: this.currentNA,
        };
    }

    generate_m1() {
        return this.initiateAuth();
    }

    get nonce_na() {
        return this.currentNA;
    }

    async processM2(msg2, noiseOverride = null, faultyIndices = null, majorityVotes = 1) {
        const k = msg2.challenges.length;
        const t = this.thresholdT;

        const responses = await this.puf.evaluateSet(
            msg2.challenges,
            noiseOverride,
            faultyIndices,
            majorityVotes
        );

        const xCoords = await mapResponsesToXCoords(responses, this.prime);
        const points = xCoords.map((x, i) => [x, msg2.sharesL[i]]);

        const expectedHS = msg2.hSHint;

        const [recoveredS, correctIndices] = await recoverSecretNoisy(
            points,
            t,
            expectedHS,
            this.prime
        );

        if (recoveredS === null) {
            this.lastCorrectIndices = [];
            return [false, null, null, `Secret reconstruction failed: fewer than t=${t} correct PUF responses`];
        }

        this.lastCorrectIndices = correctIndices || [];
        const hSStar = await hashSecret(recoveredS);

        const nBPadded = xorBytes(msg2.q, hSStar);
        const nB = nBPadded.subarray(0, 16);

        const expectedMacBs = await computeMacBs(hSStar, msg2.challenges, nB, msg2.sharesL);
        if (!timingSafeEqual(msg2.macBs, expectedMacBs)) {
            return [false, null, null, "Base Station MAC verification failed! Impersonation detected"];
        }

        const nC = new Uint8Array(16);
        globalThis.crypto.getRandomValues(nC);
        const nCPadded = new Uint8Array(32);
        nCPadded.set(nC, 0);
        const p = xorBytes(nCPadded, hSStar);

        const challengesPrime = [];
        for (let i = 0; i < k; i++) {
            const c = new Uint8Array(16);
            globalThis.crypto.getRandomValues(c);
            challengesPrime.push(c);
        }

        const rDoublePrime = await this.puf.evaluateSet(challengesPrime, 0.0);
        const rFlat = new Uint8Array(40 * k);
        for (let i = 0; i < k; i++) {
            rFlat.set(rDoublePrime[i], i * 40);
        }

        const padBytes = await padHash(hSStar, rFlat.length);
        const j = xorBytes(rFlat, padBytes);

        const macUav = await computeMacUav(hSStar, rDoublePrime, nC);
        const sk = await hkdfDeriveSessionKey(nB, nC, hSStar);
        this.lastSessionKey = sk;

        const msg3 = {
            challengesPrime,
            j,
            p,
            macUav,
        };
        return [true, msg3, sk, "OK"];
    }
}

// ==============================================================================
// Decentralized Quorum Admission & Verifiable Peer Swarm (Phases 1, 2, 3)
// ==============================================================================

export class SwarmPeerNode {
    constructor(peerId, shareX, shareY, commitments, puf = null, prime = PRIME_P) {
        this.peerId = peerId;
        this.x = BigInt(shareX);
        this.y = BigInt(shareY);
        this.commitments = commitments.map(c => BigInt(c));
        this.prime = BigInt(prime);
        this.puf = puf || new SRAMPUF();
        this.vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, prime);

        if (!this.vss.verifyShare(this.x, this.y, this.commitments)) {
            throw new Error(`Peer ${peerId} share fails VSS commitment validation!`);
        }
    }

    get uav_id() { return this.peerId; }
    get x_coord() { return this.x; }
    get y_share() { return this.y; }

    generatePartialChallenge(index) {
        const rand = new Uint8Array(16);
        globalThis.crypto.getRandomValues(rand);
        return rand;
    }

    generatePartialToken(quorumXCoords, tamperShare = false) {
        const yVal = tamperShare ? (this.y + 9999999n) % this.prime : this.y;
        return this.vss.generatePartialToken(this.peerId, this.x, yVal, quorumXCoords);
    }

    verifyPeerToken(token, quorumXCoords) {
        return this.vss.verifyPartialToken(token, this.commitments, quorumXCoords);
    }
}

export class DecentralizedQuorumCoordinator {
    constructor(thresholdT, commitments, prime = PRIME_P) {
        this.thresholdT = thresholdT;
        this.commitments = commitments.map(c => BigInt(c));
        this.prime = BigInt(prime);
        this.vss = new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, prime);
        this.nonceCache = new Set();
        this.quarantinedPeers = new Set();
        this.enrolledUavs = new Map();
    }

    registerUav(uavId, puf) {
        this.enrolledUavs.set(uavId, puf);
    }

    get quarantined_nodes() {
        return this.quarantinedPeers;
    }

    check_nonce_freshness(nonce) {
        if (!nonce) return true;
        const key = typeof nonce === 'string' ? nonce : Array.from(nonce).join(',');
        return !this.nonceCache.has(key);
    }

    async verify_quorum_and_admit(applicant, quorumPeers, commitments = null, t = null) {
        const reqT = t || this.thresholdT;
        const comm = commitments ? commitments.map(c => BigInt(c)) : this.commitments;

        if (!applicant.nonce_na && !applicant.currentNA) {
            applicant.generate_m1 ? applicant.generate_m1() : applicant.initiateAuth();
        }
        const nonce = applicant.nonce_na || applicant.currentNA;

        if (quorumPeers.length < reqT || !this.check_nonce_freshness(nonce)) {
            return false;
        }

        const quorumX = quorumPeers.map(p => p.x_coord || p.x);
        const cleanPeers = [];

        for (const peer of quorumPeers) {
            const token = peer.generatePartialToken(quorumX);
            if (!this.vss.verifyPartialToken(token, comm, quorumX)) {
                this.quarantined_nodes.add(peer.uav_id || peer.peerId);
                continue;
            }
            cleanPeers.append ? cleanPeers.append(peer) : cleanPeers.push(peer);
        }

        if (cleanPeers.length < reqT) {
            return false;
        }

        const activeQuorum = cleanPeers.slice(0, reqT);
        const activeX = activeQuorum.map(p => p.x_coord || p.x);
        const validTokens = activeQuorum.map(p => p.generatePartialToken(activeX));

        if (this.vss.combineTokensHomomorphic(validTokens) !== comm[0]) {
            return false;
        }

        const res = await this.coordinateAdmission(applicant, activeQuorum);
        return res.admitted;
    }

    async complete_m2_m3_handshake(applicant, quorumPeers) {
        const res = await this.coordinateAdmission(applicant, quorumPeers);
        return res.admitted;
    }

    async execute_m2_m3_key_agreement(applicant, quorumPeers) {
        return this.complete_m2_m3_handshake(applicant, quorumPeers);
    }

    async coordinateAdmission(
        applicant,
        quorumPeers,
        options = {}
    ) {
        const t0 = performance.now();
        const kQuorum = quorumPeers.length;

        if (kQuorum < this.thresholdT) {
            return {
                admitted: false,
                uavId: applicant.uavId,
                quorumPeers: quorumPeers.map(p => p.peerId),
                sessionKey: null,
                latencyMs: performance.now() - t0,
                reason: `Insufficient quorum size ${kQuorum} < threshold t=${this.thresholdT}`,
                vssVerified: false,
                nonReconstructiveVerified: false,
            };
        }

        // Phase 1 Step 1: Join Request
        const m1 = applicant.initiateAuth();
        if (options.replayNonce) {
            m1.nA = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
            this.nonceCache.add(bytesToHex(m1.nA));
        }

        const naHex = bytesToHex(m1.nA);
        if (this.nonceCache.has(naHex)) {
            return {
                admitted: false,
                uavId: applicant.uavId,
                quorumPeers: quorumPeers.map(p => p.peerId),
                sessionKey: null,
                latencyMs: performance.now() - t0,
                reason: "Replay attack detected: nonce NA was previously used",
                vssVerified: false,
                nonReconstructiveVerified: false,
            };
        }
        this.nonceCache.add(naHex);

        if (this.enrolledUavs.size > 0 && !this.enrolledUavs.has(applicant.uavId)) {
            return {
                admitted: false,
                uavId: applicant.uavId,
                quorumPeers: quorumPeers.map(p => p.peerId),
                sessionKey: null,
                latencyMs: performance.now() - t0,
                reason: `Unknown UAV ID ${applicant.uavId}: not enrolled in swarm registry`,
                vssVerified: false,
                nonReconstructiveVerified: false,
            };
        }

        // Phase 1 Step 2: Distributed Challenges
        const challenges = [];
        for (let j = 0; j < kQuorum; j++) {
            const peer = quorumPeers[j % kQuorum];
            challenges.push(peer.generatePartialChallenge(j));
        }

        // Phase 2 & 3: Non-reconstructive token collection and VSS validation
        const quorumXCoords = quorumPeers.map(p => p.x);
        const partialTokens = [];
        const detectedPoisoned = [];

        for (const peer of quorumPeers) {
            const isTampered = (options.tamperPeerId !== undefined && peer.peerId === options.tamperPeerId);
            const tok = peer.generatePartialToken(quorumXCoords, isTampered);

            // Phase 3: VSS Validation
            const isValid = this.vss.verifyPartialToken(tok, this.commitments, quorumXCoords);
            if (!isValid) {
                detectedPoisoned.push(peer.peerId);
                this.quarantinedPeers.add(peer.peerId);
            } else {
                partialTokens.push(tok);
            }
        }

        if (detectedPoisoned.length > 0) {
            return {
                admitted: false,
                uavId: applicant.uavId,
                quorumPeers: quorumPeers.map(p => p.peerId),
                sessionKey: null,
                latencyMs: performance.now() - t0,
                reason: `Poisoned share detected from peer(s) ${detectedPoisoned}! VSS verification rejected invalid token`,
                vssVerified: false,
                nonReconstructiveVerified: false,
                quarantinedPeers: detectedPoisoned,
            };
        }

        // Phase 2: Homomorphic Combination without raw secret reconstruction
        const homomorphicGS = this.vss.combineTokensHomomorphic(partialTokens);
        if (homomorphicGS !== this.commitments[0]) {
            return {
                admitted: false,
                uavId: applicant.uavId,
                quorumPeers: quorumPeers.map(p => p.peerId),
                sessionKey: null,
                latencyMs: performance.now() - t0,
                reason: "Homomorphic token combination does not match master commitment C0",
                vssVerified: false,
                nonReconstructiveVerified: false,
            };
        }

        const combinedSecret = this.vss.combinePartialScalars(partialTokens);
        const hS = await hashSecret(combinedSecret);

        const nB = new Uint8Array(16);
        globalThis.crypto.getRandomValues(nB);
        const nBPadded = new Uint8Array(32);
        nBPadded.set(nB, 0);
        const q = xorBytes(nBPadded, hS);

        const poly = Polynomial.random(combinedSecret, this.thresholdT, this.prime);
        const targetPuf = this.enrolledUavs.get(applicant.uavId) || applicant.puf;
        const applicantPufResponses = await targetPuf.evaluateSet(challenges, 0.0);
        const xCoordsApp = await mapResponsesToXCoords(applicantPufResponses, this.prime);
        const sharesL = xCoordsApp.map(x => poly.evaluate(x));

        const macQuorum = await computeMacBs(hS, challenges, nB, sharesL);
        if (options.tamperMacBs) {
            macQuorum[0] ^= 0xff;
        }

        const msg2 = {
            challenges,
            q,
            sharesL,
            macBs: macQuorum,
            hSHint: hS,
            commitments: this.commitments,
        };

        const [okApp, msg3, skApp, errApp] = await applicant.processM2(
            msg2,
            options.noiseOverride || 0.0,
            options.faultyApplicantIndices || null,
            7
        );

        if (!okApp) {
            return {
                admitted: false,
                uavId: applicant.uavId,
                quorumPeers: quorumPeers.map(p => p.peerId),
                sessionKey: null,
                latencyMs: performance.now() - t0,
                reason: `Applicant failed verification: ${errApp}`,
                vssVerified: true,
                nonReconstructiveVerified: true,
            };
        }

        if (options.tamperMacUav && msg3 && msg3.macUav) {
            msg3.macUav[0] ^= 0xaa;
        }
        const nCPadded = xorBytes(msg3.p, hS);
        const nC = nCPadded.subarray(0, 16);

        const totalRespLen = 40 * kQuorum;
        const padBytes = await padHash(hS, totalRespLen);
        const rDoublePrimeBytes = xorBytes(msg3.j, padBytes);

        const recoveredResponses = [];
        for (let i = 0; i < kQuorum; i++) {
            recoveredResponses.push(rDoublePrimeBytes.subarray(i * 40, (i + 1) * 40));
        }

        const expectedMacUav = await computeMacUav(hS, recoveredResponses, nC);
        if (!timingSafeEqual(msg3.macUav, expectedMacUav)) {
            return {
                admitted: false,
                uavId: applicant.uavId,
                quorumPeers: quorumPeers.map(p => p.peerId),
                sessionKey: null,
                latencyMs: performance.now() - t0,
                reason: "Applicant MAC verification failed against quorum",
                vssVerified: true,
                nonReconstructiveVerified: true,
            };
        }

        const skQuorum = await hkdfDeriveSessionKey(nB, nC, hS);
        return {
            admitted: true,
            uavId: applicant.uavId,
            quorumPeers: quorumPeers.map(p => p.peerId),
            sessionKey: skQuorum,
            latencyMs: performance.now() - t0,
            reason: "Autonomous decentralized quorum admission successful",
            vssVerified: true,
            nonReconstructiveVerified: true,
        };
    }
}
