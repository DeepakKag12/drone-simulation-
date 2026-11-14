# Complete Project Master Guide: Presentation Flow, Protocols, Security & Viva Preparation

**Project Title:** Decentralized, Non-Reconstructive, and Verifiable UAV Swarm Mutual Authentication  
**Reference Paper:** Gaurang Bansal and Biplab Sikdar, *"Achieving Secure and Reliable UAV Authentication: A Shamir's Secret Sharing Based Approach"*, IEEE Transactions on Network and Service Management (TNSM), vol. 19, no. 4, Dec. 2022.  
**Project Team:** Group Number 24 (Subject: Cryptography)  
- **Deepak Kag** (Roll No: S20230010069)  
- **Y Sri Harsha Raju** (Roll No: S20230010269)  
- **K Hemanth** (Roll No: S20230010119)  

---

## 1. Which is the Main File to Run?

[`main.py`](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/main.py) is the **single unified master entry point** for the entire project. Depending on what you want to demonstrate to your examiner or audience, run one of the following commands:

| What You Want to Demonstrate | Exact Command to Run | What It Does |
|---|---|---|
| **1. 3D Flight Physics Simulation (Most Visual)** | `python main.py --sim` | Launches the interactive PyBullet 3D urban environment. Shows orbiting UAV fleet, ground Base Station tower, 3D laser authentication links (cyan/green/red), and live GUI parameter controls to trigger attacks. |
| **2. Web Tactical Ops-Center & Dashboard** | `python main.py --web`<br>*(or double-click `run_web.bat`)* | Starts local IPv4 HTTP server and automatically opens browser at `http://localhost:8000/`. Displays 3D WebGL viewport, live cryptographic event stream, chip-by-chip PUF response inspector, and dynamic Chart.js latency graphs. |
| **3. Step-by-Step Terminal Cryptography Walkthrough** | `python main.py --demo`<br>*(or simply `python main.py`)* | Prints a human-readable, step-by-step trace of key setup, enrollment, PUF evaluation, noisy Lagrange reconstruction, session key derivation, state ratcheting, quorum consensus, and on-the-fly poisoned share isolation. |
| **4. Complete Automated Verification Test Suite** | `python main.py --test`<br>*(or `python test_protocol.py`)* | Runs all 17 automated verification suites testing field arithmetic, threshold properties, 100 consecutive ratcheted sessions, cloned PUF defense, replay protection, MitM rejection, and VSS validation in ~80 ms. |
| **5. Client-Side JavaScript Test Suite** | `node --test shamir-web/test_protocol.mjs` | Verifies full cryptographic parity between Python and Web Crypto / JavaScript BigInt engine (12 suites pass in ~150 ms). |
| **6. Micro-Benchmarks & Evaluation Export** | `python main.py --eval` | Re-runs Section VI evaluations and exports fresh measurements to `results/benchmark_data.json` and `results/benchmark_data.csv`. |

---

## 2. Full Flow of the Baseline Paper (Bansal & Sikdar, 2022)

### 2.1 The Core Intuition of the Paper
Traditional cryptographic protocols require exact bit matches. If a key or password is off by a single bit, hashing or decryption fails completely. However, hardware Physical Unclonable Functions (PUFs) are **fuzzy**: temperature shifts and voltage droop cause 2% to 10% of SRAM bits to flip randomly.

Traditional systems fix this using **Fuzzy Extractors** or **BCH error-correcting codes**, which transmit public helper data (error syndromes). But helper data leaks information and drains drone compute.

**Bansal & Sikdar's breakthrough idea:** Instead of treating PUF errors with helper data, formulate error tolerance as a **Shamir $(t, k)$ polynomial threshold reconstruction problem**:
- The Base Station evaluates a secret polynomial at $k$ points corresponding to nominal PUF responses.
- In the field, as long as any $t$ of the $k$ challenge-response pairs are noise-free, the drone can uniquely recover the polynomial secret $S = f(0)$ using Lagrange interpolation.

### 2.2 Step-by-Step Handshake Walkthrough

```
   UAV Node (D_i)                              Ground Base Station (BS)
(32-bit OTP ID, SRAM PUF)                      (CRP Database, Nonce Cache)
         |                                                 |
         | ===== STAGE 1: FACTORY ENROLLMENT (Secure) ===== |
         |                                                 | Samples master secret S in F_p*
         |                                                 | Builds poly f(x) of degree t-1
         | <--- Sends k random challenges C_1..C_k ------- |
Evaluates clean R'_j = PUF(C_j)                            |
         | --- Sends clean responses R'_1..R'_k ---------> |
         |                                                 | Maps x_j = Map(R'_j) in F_p*
         |                                                 | Computes shares L_j = f(x_j) mod p
         |                                                 | Stores [uav_id, C, L, H(S)]
         |                                                 | Erases S and R' from RAM
         |                                                 |
         | ===== STAGE 2: MUTUAL AUTHENTICATION (RF) ===== |
         |                                                 |
         | --- M1: [uav_id, N_A] ------------------------> | Verifies uav_id in database
         |     (128-bit fresh nonce N_A)                   | Rejects if N_A seen (Anti-Replay)
         |                                                 | Samples 128-bit nonce N_B
         |                                                 | Masks Q = N_B XOR H(S)
         |                                                 | Computes MAC_BS = HMAC(H(S), ...)
         | <--- M2: [C, Q, L, MAC_BS, H(S)] -------------- |
         |                                                 |
Evaluates noisy R_j = PUF(C_j)                             |
Maps x_j = Map(R_j)                                        |
Interpolates points (x_j, L_j) -> S*                       |
Verifies SHA256(S*) == H(S)                                |
Unmasks N_B = Q XOR H(S*)                                  |
Verifies MAC_BS (Base Station Authenticated!)              |
Samples fresh nonce N_C & challenges C'                    |
Evaluates new responses R'' = PUF(C')                      |
Masks P = N_C XOR H(S*), J = R'' XOR PAD(H(S*))            |
Derives Session Key Sk = HKDF(N_B || N_C, H(S*))           |
Computes MAC_UAV = HMAC(H(S*), R'' || H(S*) || N_C)        |
         | --- M3: [C', J, P, MAC_UAV] ------------------> |
         |                                                 | Unmasks N_C = P XOR H(S)
         |                                                 | Decrypts R'' = J XOR PAD(H(S))
         |                                                 | Verifies MAC_UAV (UAV Authenticated!)
         |                                                 | Derives identical Sk = HKDF(...)
         |                                                 |
         | ===== STAGE 3: CONTINUOUS STATE RATCHETING ==== |
         |                                                 | Samples fresh secret S_new
         |                                                 | Builds fresh poly f_new(x)
         |                                                 | Updates [C:=C', L:=L', H(S):=H(S_new)]
         |                                                 | Permanently wipes old CRPs
```

---

## 3. Cryptographic Primitives & Security Mechanisms Used

### 3.1 Hardware Security: SRAM PUF & Noise Filtering
- **Physical Unclonability:** Uses microscopic transistor threshold variations in uninitialized cross-coupled SRAM inverters. Responses vanish on power-down. Physical probing destroys transistor capacitance, preventing reverse-engineering.
- **Bit-Flip Noise Model:** Evaluates responses under 4 operational regimes: Ideal ($0\%$), Normal ($2\%$), Hot/Low-Voltage ($5\%$), and Aged ($10\%$).
- **Temporal Majority Voting:** Queries each SRAM address 7 consecutive times in flight and takes the majority bit value, reducing ambient bit-flip noise before cryptographic mapping.

### 3.2 Finite Field Arithmetic over Mersenne Prime $\mathbb{F}_p$
- **Field Modulus:** Mersenne prime $p = 2^{127} - 1 = 170,141,183,460,469,231,731,687,303,715,884,105,727$.
- **Exact Modular Inversion:** No floating-point divisions! Uses Extended Euclidean Algorithm:
  $$\gcd(a, p) = 1 \implies a \cdot x + p \cdot y = 1 \implies a^{-1} \equiv x \pmod p$$
- **Fast Reduction:** Since $p = 2^{127}-1$, reduction is computed via bitwise shifts: $(x \ \& \ p) + (x \gg 127)$.

### 3.3 Shamir $(t, k)$ Secret Sharing & $O(t)$ Barycentric Interpolation
- **Polynomial Definition:** Strict degree $t-1$:
  $$f(x) = S + a_1 x + a_2 x^2 + \dots + a_{t-1} x^{t-1} \pmod p$$
- **Barycentric Interpolation ($O(t)$ operations):** Precomputes barycentric weights $w_i = \prod_{j \neq i} \frac{1}{x_i - x_j} \pmod p$ to reconstruct $S = f(0)$ in linear time rather than quadratic $O(t^2)$ time.
- **Hybrid Error Recovery:** Uses Berlekamp-Welch decoding for fast algebraic error localization, backed by combinatorial subset search against hash commitment $H(S)$.

### 3.4 Wire Authentication, Freshness & Key Derivation
- **Anti-Replay Nonce Cache:** Nonces $N_A, N_B, N_C$ are 128-bit cryptographically secure random values. Observed nonces are cached; replayed messages are dropped and quarantined.
- **Integrity & Origin Authentication:** HMAC-SHA256 tags authenticate messages $M_2$ and $M_3$ using constant-time string comparison (`hmac.compare_digest`).
- **Forward-Secret Key Agreement:** Session key $S_k$ is derived via HKDF-SHA256 (RFC 5869):
  $$S_k = \text{HKDF-SHA256}(\text{ikm} = N_B \parallel N_C, \text{salt} = H(S), \text{info} = \text{"UAV-SESSION-KEY"})$$
- **State Ratcheting:** After every successful session, old challenges and shares are overwritten with fresh values. Leaking a future key reveals zero mathematical information about past sessions.

---

## 4. The Three Paper Limitations & Our Implemented Improvements

| Paper Limitation | Threat & Operational Impact | Literature Foundation | Our Implemented Solution |
|---|---|---|---|
| **1. Base Station Centralization (SPOF)** | Entire protocol relies on an online Ground Base Station. In BVLOS flight, mountain valleys, or under RF electronic jamming, authentication halts completely. | **URSA** (Luo et al., IEEE/ACM ToN, 2004) | **Phase 1: Decentralized Quorum Admission.** An ad-hoc quorum of $K \ge t$ active neighboring swarm drones collectively generates distributed challenges and admits new nodes without any Base Station. |
| **2. Leader Plaintext Secret Exposure** | Gathering raw shares $(x_i, y_i)$ at a leader drone reconstructs master secret $S$ in plaintext volatile RAM. Capturing the leader exposes $S$ and compromises the entire fleet. | **Gennaro et al.** (EUROCRYPT 1996) | **Phase 2: Non-Reconstructive Threshold Verification.** Quorum peers compute masked tokens $T_i = g^{y_i w_i} \pmod P$. Coordinator verifies $\prod T_i \equiv g^S \equiv C_0 \pmod P$ homomorphically. Master secret $S$ is **never instantiated in RAM**. |
| **3. Vulnerability to Poisoned Shares** | Standard Shamir secret sharing lacks verifiability. A single compromised or noisy peer sending a forged share $(x_i, \tilde{y}_i)$ collapses consensus with zero attribution (silent DoS). | **Feldman VSS** (IEEE SFCS 1987) | **Phase 3: Verifiable Secret Sharing Public Commitments.** Setup publishes $C_j = g^{a_j} \pmod P$. Quorum validates $g^{y_i} \equiv \prod C_j^{x_i^j} \pmod P$. Poisoned shares are detected and quarantined on-the-fly. |

---

## 5. Presentation Flow (Slide-by-Slide Walkthrough)

When presenting this project to your faculty, professors, or exam committee, follow this exact 10-slide sequence:

```
Slide 1: Title & Group 24 Details
Slide 2: Motivation & The Vulnerability of UAV Communications
Slide 3: Why Existing Approaches Fail (PKI & Flash Keys)
Slide 4: Hardware Root-of-Trust: SRAM PUF & Noise Challenge
Slide 5: Baseline Paper Architecture: Bansal & Sikdar (2022)
Slide 6: The Three Critical Limitations Identified in the Paper
Slide 7: Our Proposed Architectural Upgrades (Phases 1, 2, and 3)
Slide 8: Full-Stack Implementation (Python + WebCrypto + PyBullet 3D)
Slide 9: Experimental Results & Benchmarks (Table IV Parity, FAR, Latency)
Slide 10: Conclusion & Live Demonstration
```

### Slide 1: Title & Team Introduction
- **Title:** Decentralized, Non-Reconstructive, and Verifiable UAV Swarm Mutual Authentication
- **Team:** Group Number 24 (Deepak Kag, Y Sri Harsha Raju, K Hemanth)
- **Subject:** Cryptography / Network Security
- **Opening Statement:** *"Good morning respected evaluators. Today we present the complete implementation, mathematical formalization, and three-phase architectural upgrade of the threshold PUF-based UAV authentication protocol proposed by Bansal and Sikdar in IEEE Transactions on Network and Service Management, 2022."*

### Slide 2: Motivation & Problem Context
- Multi-drone swarms operate autonomously over open, unencrypted RF wireless channels.
- Drones must mutually authenticate before sharing flight vectors or mission data.
- **Threat Model:** Dolev-Yao attacker with total RF channel control (can replay, eavesdrop, tamper) **plus physical device capture** of downed drones.

### Slide 3: Why Traditional Solutions Fail
- **Public Key Infrastructure (PKI):** Heavy elliptic curve pairings and heavy certificate chains consume too much CPU power and drain battery flight time.
- **Symmetric Keys in Flash (EEPROM):** If a single drone crashes or is captured, memory extraction (JTAG/DPA) extracts the key and compromises the entire swarm.
- **Fuzzy Extractors:** Leaks public helper data (error syndromes) over the air and requires heavy BCH decoding.

### Slide 4: Hardware Root-of-Trust: SRAM PUF
- Exploit microscopic silicon transistor threshold mismatches at chip power-on.
- Provides a device-unique 320-bit silicon fingerprint.
- Zero static keys stored in memory—tampering physically destroys the PUF.
- **The Catch:** 2%–10% environmental bit-flip noise prevents standard cryptographic hashing.

### Slide 5: The Bansal & Sikdar Protocol (2022)
- Formulates PUF noise as a Shamir $(t, k)$ polynomial threshold problem.
- Clean enrollment at Base Station generates shares $L_j = f(x_j)$.
- Field authentication: UAV recovers candidate secret $S^* = f(0)$ as long as at least $t$ of $k$ PUF responses are noise-free.
- Continuous state ratcheting gives forward secrecy.

### Slide 6: Three Critical Limitations Identified
- **Limitation 1:** Base Station Centralization—single point of failure if ground communications are jammed.
- **Limitation 2:** Plaintext Secret Exposure—leader drone collecting shares holds $S$ in RAM, creating a single point of capture.
- **Limitation 3:** Poisoned Shares—standard Shamir cannot identify forged shares, causing silent consensus collapse.

### Slide 7: Our Three-Phase Architectural Upgrades
- **Phase 1 (Decentralized Quorum):** Swarm peer nodes form an ad-hoc quorum ($K \ge t$) to issue distributed challenges and admit nodes in deep-field BVLOS missions.
- **Phase 2 (Non-Reconstructive Verification):** Safe prime group $\mathbb{Z}_P^*$. Quorum peers send masked tokens $T_i = g^{y_i w_i} \pmod P$. Coordinator checks $\prod T_i \equiv g^S \equiv C_0 \pmod P$ without ever materializing $S$ in memory!
- **Phase 3 (Verifiable Secret Sharing):** Public coefficient commitments $C_j = g^{a_j} \pmod P$. Poisoned shares are detected and quarantined on-the-fly.

### Slide 8: Implementation Architecture
- **Dual Engine:** Pure Python 3.12 cryptographic core mirrored in ECMAScript 2024 BigInt + WebCrypto API.
- **Visuals:** 3D PyBullet physics simulator with orbiting flight dynamics, command tower, and dynamic 3D laser telemetry links.
- **Workbench:** Tactical military Web Ops-Center with live terminal and Chart.js graphs.

### Slide 9: Experimental Results & Benchmarks
- **Handshake Latency:** Baseline takes $731.9\ \mu\text{s}$; Quorum + VSS takes $1.03\ \text{ms}$ (negligible $300\ \mu\text{s}$ overhead for complete zero-knowledge security).
- **Storage:** Exactly 352 bits on UAV (zero flash memory used).
- **Communication:** 1,792 bits wire overhead ($k=5$).
- **Security:** 0.0000% False Acceptance Rate (0 / 200 rogue drones admitted).
- **Test Coverage:** 17 Python test suites and 12 Node.js test suites pass 100%.

### Slide 10: Conclusion & Live Demonstration
- Successfully transitioned theoretical research into a robust, decentralized, capture-resilient swarm defense system.
- Transition to live demo: run `python main.py --sim` or open web dashboard via `python serve.py`.

---

## 6. Comprehensive Viva Questions & Model Answers

### Category A: Core Concepts & Motivation

#### Q1: What is the primary novelty of the Bansal & Sikdar (2022) protocol?
**Answer:** The primary novelty is eliminating helper-data error syndromes in PUF-based authentication. Previous PUF protocols relied on fuzzy extractors or BCH error-correcting codes, which leak helper data over the air and incur heavy computational overhead. Bansal & Sikdar formulated PUF noise tolerance as a Shamir $(t, k)$ polynomial threshold secret sharing problem, where any $t$ noise-free challenge-response pairs reconstruct the master secret $S$ without leaking error syndromes.

#### Q2: What is an SRAM PUF and why is it considered unclonable?
**Answer:** An SRAM PUF (Physical Unclonable Function) exploits uncontrollable, sub-micron physical variations in silicon transistor geometry introduced during semiconductor manufacturing. When cross-coupled inverter cells power on, threshold voltage imbalances force each cell into a deterministic state (0 or 1). Because these variations are an intrinsic physical consequence of silicon crystal structures, they cannot be manufactured or cloned even by the original chip foundry. Furthermore, PUF responses exist only while powered; power-down destroys the key in volatile memory, preventing offline physical probing.

#### Q3: Why can't we simply store a secret cryptographic key in the drone's flash memory (EEPROM)?
**Answer:** Drones operate in physically exposed airspaces and are susceptible to mechanical capture, crashes, or net interdiction. If an attacker acquires a downed drone with keys stored in non-volatile flash or EEPROM, they can perform side-channel Differential Power Analysis (DPA), bus sniffing, or decapsulation with micro-probing to extract the static key. A single extracted key permanently compromises the entire fleet. PUFs eliminate this attack vector because zero secret keys are stored in non-volatile memory.

---

### Category B: Cryptographic Mathematics & Finite Fields

#### Q4: Why is the polynomial degree $t-1$ and not $t$?
**Answer:** By the Fundamental Theorem of Algebra, a polynomial of degree $d$ requires exactly $d+1$ distinct points to uniquely determine its coefficients. In a $(t, k)$ threshold scheme, we require that any $t$ points uniquely reconstruct the polynomial constant term $f(0) = S$. Therefore, the polynomial must have degree $d = t - 1$. The original Bansal & Sikdar paper ambiguously mentioned degree $t$ while summing over $t$ points, which was a mathematical inconsistency that we corrected in our formalization.

#### Q5: Why do we use Mersenne prime field $\mathbb{F}_p$ ($p = 2^{127}-1$) instead of standard floating-point division?
**Answer:** Standard floating-point division causes truncation and rounding errors that destroy cryptographic precision. Cryptographic secret sharing requires operations over a Galois field $\mathbb{F}_p$. In $\mathbb{F}_p$, division $a / b$ is computed as modular multiplication by the multiplicative inverse: $a \cdot b^{-1} \pmod p$. Using Mersenne prime $p = 2^{127}-1$ allows modular inversion via the Extended Euclidean Algorithm ($\gcd(b, p) = 1 \implies b \cdot u + p \cdot v = 1$) and enables high-speed modular reduction using bitwise shifts ($(x \ \& \ p) + (x \gg 127)$).

#### Q6: What is the computational advantage of Barycentric Lagrange Interpolation?
**Answer:** Standard Lagrange interpolation requires $O(t^2)$ field operations because for each of the $t$ points, a product of $t-1$ terms must be re-evaluated. Barycentric interpolation rewrites the formula using precalculated barycentric weights:
$$w_i = \prod_{j \neq i} \frac{1}{x_i - x_j} \pmod p$$
Once weights are computed, evaluating $f(0)$ takes only $O(t)$ scalar multiplications and additions, yielding a 3x to 5x speedup during real-time flight authentication.

---

### Category C: Paper Limitations & Upgrades

#### Q7: What are the three critical architectural limitations of the baseline paper?
**Answer:**
1. **Centralized Base Station Single Point of Failure:** Total dependency on an online Ground Base Station for every handshake, freezing swarm admission in RF-jammed or BVLOS environments.
2. **Leader Plaintext Secret Exposure:** Gathering raw shares $(x_i, y_i)$ at a leader drone to reconstruct $S = f(0)$ exposes $S$ in volatile RAM, creating a single point of capture.
3. **Poisoned Share Vulnerability:** Standard Shamir secret sharing lacks share verifiability. A compromised peer submitting a fake share causes Lagrange interpolation to yield $S^* \neq S$, causing silent consensus failure with zero attribution.

#### Q8: How does Phase 1 (Decentralized Quorum Admission) work?
**Answer:** Inspired by the URSA mobile ad-hoc network model (Luo et al., 2004), Phase 1 replaces the Base Station with an ad-hoc quorum of $K$ neighboring active swarm drones ($K \ge t$). When an applicant broadcasts a join request with a fresh nonce $N_A$, each quorum peer contributes an independent random challenge $C_i$. The quorum peers collectively verify the applicant without requiring long-distance base station connectivity.

#### Q9: How does Phase 2 prevent plaintext secret exposure in leader memory?
**Answer:** Phase 2 implements Gennaro et al.'s homomorphic threshold verification in a safe prime discrete-logarithm group $\mathbb{Z}_P^*$. Quorum peers never send raw shares $(x_i, y_i)$. Instead, each peer computes its localized Lagrange weight $w_i$ at $x=0$ and calculates a masked exponentiated verification token:
$$T_i = g^{y_i w_i \pmod p} \pmod P$$
The coordinator combines the tokens homomorphically via modular multiplication:
$$\prod_{i \in \mathcal{Q}} T_i \equiv g^{\sum y_i w_i} \equiv g^{f(0)} \equiv g^S \equiv C_0 \pmod P$$
The coordinator checks whether $\prod T_i$ equals the public commitment $C_0$. Under the Computational Diffie-Hellman assumption, extracting $S$ from $g^S$ is computationally intractable. Thus, **master secret $S$ is never instantiated in RAM**.

#### Q10: How does Phase 3 (Feldman VSS) detect poisoned shares?
**Answer:** During initial polynomial setup, public commitments to the polynomial coefficients are published: $C_j = g^{a_j} \pmod P$ for $j \in \{0, \dots, t-1\}$. When a peer submits its share or token, the coordinator validates that:
$$g^{y_i} \equiv \prod_{j=0}^{t-1} (C_j)^{(x_i^j \bmod p)} \pmod P$$
If a rogue or compromised peer injects a tampered share $\tilde{y}_i$, the discrete-log equality fails. The coordinator immediately rejects the share and places the offending peer ID into a persistent quarantine registry, preventing Denial-of-Service attacks.

---

### Category D: Threat Vectors & Protocol Defense

#### Q11: How does the protocol prevent Replay Attacks?
**Answer:** Every authentication handshake requires freshly generated 128-bit cryptographically secure pseudorandom nonces ($N_A, N_B, N_C$). The verifier maintains an ephemeral anti-replay nonce cache. If an adversary intercepts and replays Message 1 ($M_1$), the cache flags $N_A$ as already seen, terminates the session, and triggers an adversarial alert.

#### Q12: How does the protocol achieve Forward Secrecy?
**Answer:** Forward secrecy is guaranteed through continuous state ratcheting. At the end of every successful authentication round (Message 3), the verifier overwrites its stored state by sampling a fresh master secret $S_{new}$, constructing a new polynomial $f_{new}(x)$, and computing fresh shares $L'$ over the new challenge responses $R''$. Old challenge-response pairs are wiped. Even if an adversary compromises a future ephemeral key, they cannot decrypt past session traffic.

#### Q13: What is the False Acceptance Rate (FAR) of the system?
**Answer:** In our empirical evaluation over 200 adversarial trials with rogue drones equipped with randomized PUF silicon seeds attempting unauthorized entry, zero false admissions occurred, yielding an empirical $\text{FAR} = 0.0000\%$. The adversary's reconstructed secret $S^*$ fails the commitment check $\text{SHA256}(S^*) == H(S)$ with overwhelming probability ($1 - 1/2^{127}$).

#### Q14: What is the latency overhead of your three-phase upgrade compared to the baseline paper?
**Answer:** On our workstation testbed, the baseline centralized handshake executes in **$731.9\ \mu\text{s}$** ($k=8, t=4$). Our upgraded Decentralized Quorum with Homomorphic Verification and Feldman VSS across 5 peers executes in **$1.03\ \text{ms}$**. The modest overhead of $\approx 300\ \mu\text{s}$ is negligible in comparison to 30 Hz UAV flight control loops ($33.3\ \text{ms}$ frame time) and is fully justified by the elimination of the single point of failure and single point of capture.
