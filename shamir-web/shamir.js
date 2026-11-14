/**
 * Threshold Secret Sharing and Verifiable Secret Sharing Engine (JavaScript).
 * Matches crypto/shamir.py.
 */

import {
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    modInverse,
    fieldAdd,
    fieldSub,
    fieldMul,
    fieldPow,
    commitmentPow,
    randomFieldElement,
    hashSecret,
    timingSafeEqual,
} from './field.js';

export class Polynomial {
    constructor(coefficients, prime = PRIME_P) {
        this.prime = prime;
        this.coeffs = coefficients.map(c => ((BigInt(c) % prime) + prime) % prime);
        while (this.coeffs.length > 1 && this.coeffs[this.coeffs.length - 1] === 0n) {
            this.coeffs.pop();
        }
    }

    get degree() {
        return this.coeffs.length - 1;
    }

    evaluate(x) {
        const p = this.prime;
        x = ((BigInt(x) % p) + p) % p;
        let result = 0n;
        for (let i = this.coeffs.length - 1; i >= 0; i--) {
            result = (result * x + this.coeffs[i]) % p;
        }
        return result;
    }

    static random(secret, thresholdT, prime = PRIME_P) {
        if (thresholdT < 1) throw new Error("Threshold t must be >= 1");
        const coeffs = [((BigInt(secret) % prime) + prime) % prime];
        for (let i = 1; i < thresholdT; i++) {
            coeffs.push(randomFieldElement(prime));
        }
        return new Polynomial(coeffs, prime);
    }
}

export class BarycentricInterpolator {
    constructor(xCoords, prime = PRIME_P) {
        this.prime = prime;
        this.xCoords = xCoords.map(x => ((BigInt(x) % prime) + prime) % prime);
        this.t = this.xCoords.length;
        const seen = new Set(this.xCoords.map(x => x.toString()));
        if (seen.size !== this.t) {
            throw new Error("All x-coordinates must be distinct for interpolation");
        }
        this.weights = this._computeWeights();
    }

    _computeWeights() {
        const t = this.t;
        const p = this.prime;
        const xs = this.xCoords;

        if (t === 0) return [];
        if (t === 1) return [1n];

        const prefix = new Array(t + 1).fill(1n);
        for (let i = 0; i < t; i++) {
            const term = ((-xs[i] % p) + p) % p;
            prefix[i + 1] = (prefix[i] * term) % p;
        }

        const suffix = new Array(t + 1).fill(1n);
        for (let i = t - 1; i >= 0; i--) {
            const term = ((-xs[i] % p) + p) % p;
            suffix[i] = (suffix[i + 1] * term) % p;
        }

        const weights = [];
        for (let i = 0; i < t; i++) {
            const num = (prefix[i] * suffix[i + 1]) % p;
            const xi = xs[i];
            let den = 1n;
            for (let j = 0; j < t; j++) {
                if (i !== j) {
                    const diff = ((xi - xs[j]) % p + p) % p;
                    den = (den * diff) % p;
                }
            }
            const invDen = modInverse(den, p);
            weights.push((num * invDen) % p);
        }
        return weights;
    }

    reconstruct(yValues) {
        if (yValues.length !== this.t) {
            throw new Error(`Expected ${this.t} y-values, got ${yValues.length}`);
        }
        const p = this.prime;
        let secret = 0n;
        for (let i = 0; i < this.t; i++) {
            const yi = ((BigInt(yValues[i]) % p) + p) % p;
            const term = (yi * this.weights[i]) % p;
            secret = (secret + term) % p;
        }
        return secret;
    }
}

export function lagrangeInterpolateAtZero(points, prime = PRIME_P) {
    const xs = points.map(pt => pt[0]);
    const ys = points.map(pt => pt[1]);
    const interpolator = new BarycentricInterpolator(xs, prime);
    return interpolator.reconstruct(ys);
}

// ==============================================================================
// Verifiable Secret Sharing (VSS) & Non-Reconstructive Token Operations
// ==============================================================================

export class VerifiableSecretSharing {
    constructor(
        generator = COMMITMENT_GENERATOR_G,
        commitmentP = COMMITMENT_PRIME_P,
        secretP = PRIME_P
    ) {
        this.g = BigInt(generator);
        this.P = BigInt(commitmentP);
        this.p = BigInt(secretP);
    }

    generateCommitments(coefficients) {
        return coefficients.map(a => commitmentPow(this.g, a, this.P, this.p));
    }

    createPolynomialAndCommitments(secret, thresholdT) {
        const poly = Polynomial.random(secret, thresholdT, this.p);
        const commitments = this.generateCommitments(poly.coeffs);
        return { poly, commitments };
    }

    verifyShare(x, y, commitments) {
        const xBig = BigInt(x);
        const yBig = BigInt(y);

        const lhs = commitmentPow(this.g, yBig, this.P, this.p);

        let rhs = 1n;
        let xPow = 1n;
        for (const cJ of commitments) {
            const term = commitmentPow(cJ, xPow, this.P, this.p);
            rhs = (rhs * term) % this.P;
            xPow = (xPow * xBig) % this.p;
        }

        return lhs === rhs;
    }

    computeLagrangeWeight(targetX, quorumXCoords) {
        const p = this.p;
        const tx = ((BigInt(targetX) % p) + p) % p;
        let num = 1n;
        let den = 1n;
        for (const xjRaw of quorumXCoords) {
            const xj = ((BigInt(xjRaw) % p) + p) % p;
            if (xj !== tx) {
                num = (num * (-xj)) % p;
                den = (den * (tx - xj)) % p;
            }
        }
        const invDen = modInverse(((den % p) + p) % p, p);
        return ((num * invDen) % p + p) % p;
    }

    generatePartialToken(peerId, xI, yI, quorumXCoords) {
        const wI = this.computeLagrangeWeight(xI, quorumXCoords);
        const sigmaI = (BigInt(yI) * wI) % this.p;
        const tokenT = commitmentPow(this.g, sigmaI, this.P, this.p);
        return {
            peerId,
            x: BigInt(xI),
            sigma: sigmaI,
            tokenT,
        };
    }

    verifyPartialToken(token, commitments, quorumXCoords) {
        const wI = this.computeLagrangeWeight(token.x, quorumXCoords);

        let expectedGY = 1n;
        let xPow = 1n;
        for (const cJ of commitments) {
            const term = commitmentPow(cJ, xPow, this.P, this.p);
            expectedGY = (expectedGY * term) % this.P;
            xPow = (xPow * BigInt(token.x)) % this.p;
        }

        const expectedToken = commitmentPow(expectedGY, wI, this.P, this.p);
        return expectedToken === token.tokenT;
    }

    combineTokensHomomorphic(tokens) {
        let combined = 1n;
        for (const tok of tokens) {
            combined = (combined * BigInt(tok.tokenT)) % this.P;
        }
        return combined;
    }

    combinePartialScalars(tokens) {
        let s = 0n;
        for (const tok of tokens) {
            s = (s + BigInt(tok.sigma)) % this.p;
        }
        return s;
    }
}

// ==============================================================================
// Polynomial division and Linear solver in BigInt F_p
// ==============================================================================

function polyDivMod(dividend, divisor, prime = PRIME_P) {
    const p = prime;
    let divd = dividend.map(c => ((BigInt(c) % p) + p) % p);
    while (divd.length > 1 && divd[divd.length - 1] === 0n) divd.pop();
    let divs = divisor.map(c => ((BigInt(c) % p) + p) % p);
    while (divs.length > 1 && divs[divs.length - 1] === 0n) divs.pop();

    if (divs.length === 1 && divs[0] === 0n) {
        throw new Error("Division by zero polynomial");
    }

    const quot = new Array(Math.max(1, divd.length - divs.length + 1)).fill(0n);
    const rem = [...divd];
    const invLead = modInverse(divs[divs.length - 1], p);

    while (rem.length >= divs.length && !(rem.length === 1 && rem[0] === 0n)) {
        const degDiff = rem.length - divs.length;
        const factor = (rem[rem.length - 1] * invLead) % p;
        quot[degDiff] = factor;

        for (let i = 0; i < divs.length; i++) {
            const pos = degDiff + i;
            rem[pos] = ((rem[pos] - factor * divs[i]) % p + p) % p;
        }

        while (rem.length > 1 && rem[rem.length - 1] === 0n) rem.pop();
    }
    return [quot, rem];
}

function solveLinearSystem(matrix, vector, prime = PRIME_P) {
    const p = prime;
    const m = matrix.length;
    const n = m > 0 ? matrix[0].length : 0;
    if (m === 0 || n === 0) return null;

    const aug = matrix.map((row, r) => [...row.map(c => ((BigInt(c) % p) + p) % p), ((BigInt(vector[r]) % p) + p) % p]);

    let lead = 0;
    const pivotCols = [];
    for (let r = 0; r < m; r++) {
        if (lead >= n) break;
        let i = r;
        while (i < m && aug[i][lead] === 0n) i++;
        if (i === m) {
            lead++;
            continue;
        }

        const tmp = aug[r];
        aug[r] = aug[i];
        aug[i] = tmp;

        const invPivot = modInverse(aug[r][lead], p);
        for (let c = lead; c <= n; c++) {
            aug[r][c] = (aug[r][c] * invPivot) % p;
        }

        for (let otherR = 0; otherR < m; otherR++) {
            if (otherR !== r && aug[otherR][lead] !== 0n) {
                const factor = aug[otherR][lead];
                for (let c = lead; c <= n; c++) {
                    aug[otherR][c] = ((aug[otherR][c] - factor * aug[r][c]) % p + p) % p;
                }
            }
        }
        pivotCols.push([r, lead]);
        lead++;
    }

    for (let r = 0; r < m; r++) {
        const allZeros = aug[r].slice(0, n).every(v => v === 0n);
        if (allZeros && aug[r][n] !== 0n) return null;
    }

    const solution = new Array(n).fill(0n);
    for (let idx = pivotCols.length - 1; idx >= 0; idx--) {
        const [r, col] = pivotCols[idx];
        let val = aug[r][n];
        for (let c = col + 1; c < n; c++) {
            val = ((val - aug[r][c] * solution[c]) % p + p) % p;
        }
        solution[col] = (val % p + p) % p;
    }
    return solution;
}

export function berlekampWelchDecode(points, thresholdT, prime = PRIME_P) {
    const k = points.length;
    const p = prime;
    if (k < thresholdT) return null;

    const maxErrors = Math.floor((k - thresholdT) / 2);
    if (maxErrors < 1) {
        try {
            return lagrangeInterpolateAtZero(points.slice(0, thresholdT), prime);
        } catch (e) {
            return null;
        }
    }

    for (let e = maxErrors; e > 0; e--) {
        const numQ = thresholdT + e;
        const numE = e;
        const matrix = [];
        const vector = [];

        for (const [xi, yi] of points) {
            const row = [];
            let xPow = 1n;
            for (let q = 0; q < numQ; q++) {
                row.push(xPow);
                xPow = (xPow * xi) % p;
            }

            xPow = 1n;
            const negYi = ((-yi % p) + p) % p;
            for (let em = 0; em < numE; em++) {
                row.push((negYi * xPow) % p);
                xPow = (xPow * xi) % p;
            }
            matrix.push(row);

            let xiPowE = 1n;
            for (let i = 0; i < e; i++) xiPowE = (xiPowE * xi) % p;
            vector.push((yi * xiPowE) % p);
        }

        const sol = solveLinearSystem(matrix, vector, p);
        if (!sol) continue;

        const qCoeffs = sol.slice(0, numQ);
        const eCoeffs = [...sol.slice(numQ), 1n];

        try {
            const [quotient, remainder] = polyDivMod(qCoeffs, eCoeffs, p);
            if (remainder.every(r => r === 0n)) {
                const poly = new Polynomial(quotient, p);
                if (poly.degree <= thresholdT - 1) {
                    let matches = 0;
                    for (const [xi, yi] of points) {
                        if (poly.evaluate(xi) === ((yi % p) + p) % p) matches++;
                    }
                    if (matches >= thresholdT) {
                        return poly.evaluate(0n);
                    }
                }
            }
        } catch (err) {
            continue;
        }
    }

    try {
        return lagrangeInterpolateAtZero(points.slice(0, thresholdT), prime);
    } catch (e) {
        return null;
    }
}

function* getCombinations(arr, size) {
    if (size === 1) {
        for (const item of arr) yield [item];
        return;
    }
    for (let i = 0; i <= arr.length - size; i++) {
        const head = arr[i];
        const tailCombos = getCombinations(arr.slice(i + 1), size - 1);
        for (const combo of tailCombos) {
            yield [head, ...combo];
        }
    }
}

export async function recoverSecretNoisy(
    points,
    thresholdT,
    expectedHS,
    prime = PRIME_P,
    maxSubsets = 5000
) {
    const k = points.length;
    if (k < thresholdT) return [null, null];

    const bwSecret = berlekampWelchDecode(points, thresholdT, prime);
    if (bwSecret !== null) {
        const hSecret = await hashSecret(bwSecret);
        if (!expectedHS || timingSafeEqual(hSecret, expectedHS)) {
            const correct = [];
            for (let i = 0; i < k; i++) {
                try {
                    const testPts = [points[i], ...points.slice(0, thresholdT).filter((_, idx) => idx !== i)].slice(0, thresholdT);
                    if (testPts.length === thresholdT) {
                        if (lagrangeInterpolateAtZero(testPts, prime) === bwSecret) {
                            correct.push(i);
                        }
                    }
                } catch (e) {}
            }
            return [bwSecret, correct.length >= thresholdT ? correct : Array.from({ length: thresholdT }, (_, i) => i)];
        }
    }

    const allIndices = Array.from({ length: k }, (_, i) => i);
    let subsetCount = 0;

    for (const subset of getCombinations(allIndices, thresholdT)) {
        subsetCount++;
        if (subsetCount > maxSubsets) break;

        const candPts = subset.map(i => points[i]);
        let candS;
        try {
            candS = lagrangeInterpolateAtZero(candPts, prime);
        } catch (e) {
            continue;
        }

        const candH = await hashSecret(candS);
        if (!expectedHS || timingSafeEqual(candH, expectedHS)) {
            const correctSet = new Set(subset);
            for (let i = 0; i < k; i++) {
                if (!correctSet.has(i)) {
                    const testPts = [points[i], ...candPts.slice(1)];
                    try {
                        if (lagrangeInterpolateAtZero(testPts, prime) === candS) {
                            correctSet.add(i);
                        }
                    } catch (e) {}
                }
            }
            return [candS, Array.from(correctSet).sort((a, b) => a - b)];
        }
    }

    return [null, null];
}
