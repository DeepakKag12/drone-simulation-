# Achieving Secure and Reliable UAV Authentication: A Shamir's Secret Sharing Based Approach
### 100% Real Research Paper Implementation & Three-Phase Architectural Upgrade
**Project Team: Group Number 24 | Subject: Cryptography**
- **Deepak Kag** (Roll No: S20230010069)
- **Y Sri Harsha Raju** (Roll No: S20230010269)
- **K Hemanth** (Roll No: S20230010119)

---

## Deliverable Documentation Index

1. [PAPER_IMPLEMENTATION.md](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/PAPER_IMPLEMENTATION.md): Complete mathematical and algorithmic breakdown of Bansal & Sikdar (2024) + the 3 upgrade phases.
2. [ARCHITECTURE.md](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/ARCHITECTURE.md): System architecture, UI-Backend-Terminal connectivity pipeline, sequence diagrams, and threat models.
3. [API_DOCUMENTATION.md](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/API_DOCUMENTATION.md): Complete REST & SSE API specification with curl examples and payload schemas.
4. [SETUP.md](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/SETUP.md): Step-by-step setup and launch commands for both terminal and web operations.
5. [EXPERIMENT_RESULTS.md](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/EXPERIMENT_RESULTS.md): Genuine CPU microsecond benchmarks, communication overhead, storage overhead, FAR (0.0000%).
6. [VALIDATION_REPORT.md](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/VALIDATION_REPORT.md): Comprehensive QA audit of all 17 Python test suites, 12 Node.js test suites, and adversarial injection vectors.

---

This repository contains the complete implementation and three-phase architectural upgrade of the mutual authentication protocol proposed by Gaurang Bansal and Biplab Sikdar in *"Achieving Secure and Reliable UAV Authentication: A Shamir's Secret Sharing Based Approach"* (IEEE Transactions, 2024).

The protocol serves as **the sole and definitive authentication system** across the entire application stack: Python cryptographic protocol engine, live multi-threaded backend server, automated test suites, CLI walkthrough, and a dark ops-center Three.js Web dashboard with live Chart.js benchmarks.

**Every action performed through the UI corresponds to real application execution and is visible in the terminal in real time.**

---

## Architecture & File Organization

```
├── crypto/                         # Core Python Cryptographic Protocol Package
│   ├── __init__.py                 # Package exports
│   ├── finite_field.py             # Prime field F_p (p = 2^127 - 1), Z_P*, HKDF-SHA256, XOR utilities
│   ├── shamir.py                   # Shamir (t, k), barycentric O(t) weights, VSS, Berlekamp-Welch
│   ├── puf.py                      # SRAM PUF simulator with bit-flip noise model & majority voting
│   └── protocol.py                 # UAV, BaseStation & Decentralized Quorum state machines
├── docs/                           # Technical Specifications & Documentation
│   ├── PROJECT_GUIDE.md            # Master Guide: Run Commands, Protocols, Presentation & Viva Prep
│   ├── PROTOCOL.md                 # Full protocol specification, math formulation, sequence diagrams
│   └── ARCHITECTURE.md             # System Architecture, Component Specifications, Security Boundaries
├── reports/                        # Academic & Technical Submission Deliverables
│   ├── REPORT.md                   # Comprehensive 9-section technical report (Markdown)
│   ├── Final_Submission_Technical_Report.pdf # Publication-ready PDF submission report
│   └── report_source.html          # Clean HTML print source template
├── results/                        # Section VI Evaluation Outputs
│   ├── benchmark_data.json         # Raw benchmark data (micro-benchmarks, noise curves, FAR)
│   └── benchmark_data.csv          # Execution time vs security level measurements
├── shamir-web/                     # Web Tactical Ops-Center & Benchmark Dashboard
│   ├── index.html                  # Dense 3-column operations workbench HTML
│   ├── style.css                   # Restrained ops-center CSS (cool slate, 1px borders)
│   ├── field.js                    # JavaScript BigInt Prime Field F_p and Web Crypto API bindings
│   ├── shamir.js                   # JS Shamir (t, k), Barycentric weights, VSS commitments
│   ├── puf.js                      # JS SRAM PUF simulator with 320-bit response and noise model
│   ├── protocol.js                 # JS UAV, Base Station & Quorum admission state machines
│   ├── script.js                   # Three.js 3D swarm rendering, Web Crypto async runner & Chart.js
│   └── test_protocol.mjs           # Node.js automated test runner (node --test)
├── main.py                         # Unified Entry Point CLI (--sim, --headless, --demo, --test, --eval, --web)
├── simulation.py                   # 3D PyBullet Drone Swarm Simulation with Base Station & attack simulation
├── serve.py                        # Pure IPv4 Web Server Launcher (http://127.0.0.1:8000)
├── test_protocol.py                # Comprehensive 17-suite automated Python verification runner
├── requirements.txt                # Python package dependencies (pybullet>=3.2.5)
├── run_web.bat                     # Windows 1-click batch launcher
└── .gitignore                      # Python bytecode and environment cache ignores
```

---

## Protocol Overview & Core Mechanisms

1. **Hardware Root-of-Trust (SRAM PUF):**
   - Each UAV is provisioned with a unique physical silicon fingerprint.
   - Generates 320-bit (40 bytes) responses for challenges $C_j$.
   - Incorporates a realistic bit-flip noise model ($p_{flip}$), with presets for Ideal (0%), Normal (~2%), Hot/Low-Voltage (~5%), and Aged (~10%).
   - Supports 7-sample on-chip temporal majority voting for reliable in-flight stabilization.

2. **Fault-Tolerant Shamir Secret Sharing:**
   - Prime field $\mathbb{F}_p$ with Mersenne prime $p = 2^{127}-1$.
   - Polynomial: $f(x) = S + a_1 x + \dots + a_{t-1} x^{t-1} \pmod p$ (degree $t-1$).
   - Any $t$ correct challenge-response points uniquely reconstruct $S = f(0)$ using $O(t)$ barycentric Lagrange interpolation weights.
   - Sub-threshold coalitions holding $< t$ responses learn zero information regarding $S$.

3. **Hybrid Point Recovery (Berlekamp-Welch + Subset Search):**
   - Fast Path: Berlekamp-Welch Reed-Solomon decoding resolves errors in polynomial time when errors $e \le \lfloor(k-t)/2\rfloor$.
   - Fallback Path: Combinatorial $t$-subset search systematically iterates candidate subsets, verifying $\text{SHA256}(S^*) == H(S)$, tolerating up to $k-t$ faulty responses.

4. **Mutual Authentication & Session Key Agreement:**
   - Step 1: $\text{UAV} \to \text{BS}: (id, N_A)$ (128-bit fresh nonce; BS checks nonce cache to thwart replays).
   - Step 2: $\text{BS} \to \text{UAV}: (C, Q = N_B \oplus H(S), L, \text{MAC}_{BS})$.
   - Step 3: UAV evaluates PUF, recovers $S^*$, validates $H(S^*)$, unmasks $N_B$, verifies $\text{MAC}_{BS}$ (BS authenticated to UAV).
   - Step 4: $\text{UAV} \to \text{BS}: (C', P = N_C \oplus H(S^*), J = R'' \oplus PAD(H(S^*)), \text{MAC}_{UAV})$. Derives $S_k = \text{HKDF}(N_B, N_C, H(S^*))$.
   - Step 5: BS recovers $N_C, R''$, verifies $\text{MAC}_{UAV}$ (UAV authenticated to BS), derives identical $S_k$.
   - Step 6: State Ratcheting: BS updates $C \leftarrow C', L \leftarrow L', H(S) \leftarrow H(S_{new})$, securely wiping old secrets and CRPs.

---

## Quickstart & Execution Guide

### 1. Run All Tests
Execute both the Python and JavaScript verification test suites:
```bash
# Python Test Suite (17 suites, 100 ratcheted sessions, attack tests)
python main.py --test

# Node.js Test Suite (12 suites, Web Crypto & BigInt engine)
node --test shamir-web/test_protocol.mjs
```

### 2. Step-by-Step Terminal Cryptography Walkthrough
Trace parameter setup, factory enrollment, noisy PUF reconstruction, MAC verification, session key derivation, and ratcheting:
```bash
python main.py --demo
```

### 3. Run Section VI Benchmarks & Evaluation
Measures primitive operations, execution time across security levels ($t=2,4,6,8$), noise resilience, and false acceptance rate (FAR):
```bash
python main.py --eval
```
*Results are saved directly to `results/benchmark_data.json` and `results/benchmark_data.csv`.*

### 4. Run 3D PyBullet Swarm Simulation
Launch the real-time 3D simulation with Base Station command tower, orbiting UAV fleet, laser telemetry beams, and interactive attack buttons:
```bash
python main.py --sim
```
*Or run in headless direct mode (automated / CI environment):*
```bash
python main.py --sim --headless
```

### 5. Launch the Web Tactical Ops-Center
Launch the interactive web operations workbench:
```bash
python main.py --web
```
*(Or use `python -m http.server 8000 --bind 127.0.0.1 --directory shamir-web`)*

Open your browser at:
- **Local URL:** `http://localhost:8000/` or `http://127.0.0.1:8000/`
*(Note: Do not navigate to `http://[::]:8000/` as Windows web browsers do not resolve `[::]` to localhost).*

Interact with:
- Three.js 3D Swarm Viewport with Base Station & laser communication beams.
- Live Cryptographic Protocol Terminal printing every step in real-time.
- Per-drone response point chips inspection tray (green for valid, red for faulty).
- Interactive controls: $t, k$, noise slider, environment presets, and attack injection buttons.
- Chart.js benchmark graphs dynamically visualizing performance and noise resilience.

---

## Architectural Upgrades (Three Sequential Phases)

Beyond the baseline centralized architecture, the codebase incorporates three advanced architectural upgrades:

1. **Phase 1: Decentralized Quorum Admission (URSA-Style Ad-Hoc Admission)**
   - Eliminates single online Base Station dependency for deep-field / disconnected tactical ops.
   - Neighboring swarm drones form a peer quorum of size $K$ to issue distributed challenges and evaluate joining applicant drones ($D_J$).

2. **Phase 2: Non-Reconstructive Threshold Verification**
   - Eliminates the single point of compromise where a coordinator reconstructs the master secret $S$ in plaintext memory.
   - Quorum drones calculate local masked partial tokens $\sigma_i = y_i w_i \pmod p$ and public verification tokens $T_i = g^{\sigma_i} \pmod P$.
   - Tokens are combined homomorphically ($\prod T_i = g^S \pmod P = C_0$) without ever exposing or instantiating $S$ in plaintext RAM.

3. **Phase 3: Verifiable Secret Sharing (VSS) Public Commitments**
   - Public coefficient commitments $C_j = g^{a_j} \pmod P$ are published at enrollment.
   - Validates incoming shares on-the-fly ($g^y \equiv \prod C_j^{x^j} \pmod P$).
   - Automatically detects, quarantines, and rejects poisoned or tampered shares in real-time.

4. **Configuration Toggle:**
   - Both modes (`BASE_STATION` and `DECENTRALIZED_QUORUM`) remain fully supported and hot-swappable via command-line flags and Web UI dropdowns.

---

## Evaluation & Comparative Summary (Paper Section VI)

| Metric | Bansal & Sikdar Paper Reported | Our Implementation (Measured) |
|---|---|---|
| **NodeMCU Execution Time** | 450 µs | 450 µs (reference) |
| **Raspberry Pi Execution Time** | 207 µs | 207 µs (reference) |
| **PC / Client Execution Time ($k=8, t=4$)** | N/A | **731.9 µs** (Python) / **~0.78 ms** (Web Crypto) |
| **Communication Cost (bits)** | 1,600 bits ($k=5$) | **1,792 bits** ($k=5$, exact serialization) / 2,552 bits ($k=8$) |
| **UAV Storage Overhead (bits)** | 352 bits | **352 bits** (OTP ID + Silicon Fingerprint) |
| **False Acceptance Rate (FAR)** | 0% | **0.0000%** (0 false accepts in 200 adversarial trials) |
| **Fault Tolerance Threshold** | Reconstructs with any $t$ of $k$ | **Verified**: Tolerates up to $k-t$ errors; rejects $> k-t$ |
| **Anti-Replay Mechanism** | Stated in informal analysis | **Enforced**: Nonce cache immediately quarantines replayed $N_A$ |
| **State Ratcheting** | CRP renewal described | **Automated**: 100 consecutive sessions with full ratchet verified |
