/**
 * SRAM PUF Simulator with Bit-Flip Noise Model (JavaScript).
 * Matches crypto/puf.py.
 */

import { hmacSha256, sha256Bytes } from './field.js';

export class SRAMPUF {
    static PRESET_IDEAL = 0.00;
    static PRESET_NORMAL = 0.02;
    static PRESET_HOT_LOW_VOLTAGE = 0.05;
    static PRESET_AGED = 0.10;

    static RESPONSE_BITS = 320;
    static RESPONSE_BYTES = 40;

    constructor(seed = null, bitFlipRate = SRAMPUF.PRESET_IDEAL) {
        if (!seed) {
            this.seed = new Uint8Array(32);
            globalThis.crypto.getRandomValues(this.seed);
        } else if (typeof seed === 'string') {
            this.seed = new TextEncoder().encode(seed);
        } else if (seed instanceof Uint8Array) {
            this.seed = seed;
        } else {
            this.seed = new Uint8Array(seed);
        }
        this.bitFlipRate = Number(bitFlipRate);
    }

    setEnvironmentPreset(presetName) {
        const presets = {
            ideal: SRAMPUF.PRESET_IDEAL,
            normal: SRAMPUF.PRESET_NORMAL,
            hot: SRAMPUF.PRESET_HOT_LOW_VOLTAGE,
            hot_low_voltage: SRAMPUF.PRESET_HOT_LOW_VOLTAGE,
            aged: SRAMPUF.PRESET_AGED,
        };
        const key = presetName.toLowerCase().trim();
        if (key in presets) {
            this.bitFlipRate = presets[key];
        } else {
            throw new Error(`Unknown preset '${presetName}'`);
        }
    }

    async computeBaseResponse(challenge) {
        const cBytes = challenge instanceof Uint8Array ? challenge : new TextEncoder().encode(challenge);

        // Challenge + 0x01
        const c1 = new Uint8Array(cBytes.length + 1);
        c1.set(cBytes);
        c1[cBytes.length] = 0x01;
        const b1 = await hmacSha256(this.seed, c1); // 32 bytes

        // Challenge + 0x02
        const c2 = new Uint8Array(cBytes.length + 1);
        c2.set(cBytes);
        c2[cBytes.length] = 0x02;
        const b2 = await hmacSha256(this.seed, c2); // 32 bytes

        const base320 = new Uint8Array(SRAMPUF.RESPONSE_BYTES);
        base320.set(b1, 0);
        base320.set(b2.subarray(0, 8), 32);
        return base320;
    }

    async evaluate(challenge, noiseOverride = null, forceCorrupt = false, majorityVotes = 1) {
        const base = await this.computeBaseResponse(challenge);
        const pFlip = noiseOverride !== null ? Number(noiseOverride) : this.bitFlipRate;

        if (pFlip <= 0.0 && !forceCorrupt) {
            return base;
        }

        // Expand bits
        const bits = [];
        for (let i = 0; i < base.length; i++) {
            const byteVal = base[i];
            for (let shift = 7; shift >= 0; shift--) {
                bits.push((byteVal >> shift) & 1);
            }
        }

        let flippedAny = false;
        for (let i = 0; i < bits.length; i++) {
            let shouldFlip = false;
            if (majorityVotes > 1) {
                let votes = 0;
                for (let v = 0; v < majorityVotes; v++) {
                    if (Math.random() < pFlip) votes++;
                }
                shouldFlip = (votes > Math.floor(majorityVotes / 2));
            } else {
                shouldFlip = (Math.random() < pFlip);
            }

            if (shouldFlip) {
                bits[i] ^= 1;
                flippedAny = true;
            }
        }

        if (forceCorrupt && !flippedAny) {
            const targetIdx = Math.floor(Math.random() * bits.length);
            bits[targetIdx] ^= 1;
        }

        // Reconstruct bytes
        const outBytes = new Uint8Array(SRAMPUF.RESPONSE_BYTES);
        for (let i = 0; i < bits.length; i++) {
            const byteIdx = Math.floor(i / 8);
            const bitOffset = 7 - (i % 8);
            outBytes[byteIdx] |= (bits[i] << bitOffset);
        }
        return outBytes;
    }

    async evaluateSet(challenges, noiseOverride = null, faultyIndices = null, majorityVotes = 1) {
        const responses = [];
        const faultSet = new Set(faultyIndices || []);
        for (let j = 0; j < challenges.length; j++) {
            if (faultSet.has(j)) {
                responses.push(await this.evaluate(challenges[j], null, true, 1));
            } else {
                responses.push(await this.evaluate(challenges[j], noiseOverride, false, majorityVotes));
            }
        }
        return responses;
    }

    clone() {
        return new SRAMPUF(this.seed.slice(), this.bitFlipRate);
    }
}

