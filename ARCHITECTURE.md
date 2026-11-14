# ARCHITECTURE.md
## System Architecture & Live Operational Pipeline Specification

**Project:** Autonomous UAV Swarm Mutual Authentication & State-Ratcheted Key Agreement  
**Group:** Group 24 (Deepak Kag, Y Sri Harsha Raju, K Hemanth)  
**System Architecture Paradigm:** Hybrid Dual-Topology (Centralized Base Station & Decentralized Peer Quorum)  
**Integration Stack:** Python 3.12 Asynchronous Backend + Multi-Threaded HTTP/SSE Server + Vanilla ES2022 Tactical Web Dashboard  

---

### 1. High-Level Architectural Model

The platform is architectured to provide zero-trust mutual authentication, physical unclonable hardware identity verification, and dynamic forward-secure session key agreement for tactical UAV fleets.

```mermaid
flowchart TD
    subgraph UI_Layer["User Interaction & Presentation Layer"]
        UI[Tactical Operations Dashboard]
        Canvas[3D Drone Airspace Visualizer]
        HUD[Telemetry HUD & Security Gauges]
        TerminalConsole[Live Synchronized Terminal Log]
    end

    subgraph Comm_Layer["Real-Time Communication Bus"]
        REST[REST API Endpoints]
        SSE[Server-Sent Events Stream /api/events]
    end

    subgraph Backend_Layer["Research Backend Engine (backend.py)"]
        Backend[ResearchBackend Controller]
        EventBus[Multi-Subscriber EventBus]
        FleetDB[Enrolled Fleet State Database]
        QuarantineDB[Dynamic Quarantine Registry]
    end

    subgraph Crypto_Layer["Cryptographic Core Engine (crypto/)"]
        Field[Finite Field F_p Arithmetic p=2^127-1]
        PUF[320-bit SRAM PUF + 7-Vote Sampling]
        Shamir[Shamir Secret Sharing + O t Barycentric]
        VSS[Feldman Verifiable Secret Sharing C_j]
        ProtocolBS[Centralized Base Station Engine]
        ProtocolQuorum[Decentralized Quorum Engine]
    end

    UI -->|HTTP POST JSON| REST
    REST --> Backend
    Backend --> Crypto_Layer
    Crypto_Layer --> Backend
    Backend -->|Push Event| EventBus
    EventBus -->|Terminal Stdout| TerminalConsole
    EventBus -->|text/event-stream| SSE
    SSE --> TerminalConsole
    Backend -->|HTTP 200 JSON| REST
    REST --> UI
    UI --> Canvas
    UI --> HUD
```

---

### 2. Dual-Topology Operational Modes

The architecture supports dynamic runtime switching between two operational topologies via a configuration toggle:

#### Mode A: Centralized Base Station (Bansal & Sikdar 2024 Baseline)
* **Application Scope:** Line-of-sight base camp operations with an active command tower.
* **Master Entity:** `CentralizedBaseStation` maintains the enrolled challenge-response database, generates 3-pass mutual challenges ($C, L, N_B$), verifies applicant MACs, and issues session confirmation.
* **Vulnerability Mitigated:** Overcomes eavesdropping and replay attacks via high-entropy nonces ($N_A, N_B$) and SHA-256 HMAC integrity tags.

#### Mode B: Decentralized Autonomous Peer Quorum (Three-Phase Upgrade)
* **Application Scope:** Deep-field, contested tactical environments beyond base-station radio horizon.
* **Master Entity:** `DecentralizedQuorumCoordinator` orchestrates a local peer group of $K \ge t$ active swarm nodes.
* **Phase 1 (Decentralized Admission):** Distributed challenge generation without central infrastructure.
* **Phase 2 (Non-Reconstructive Aggregation):** Quorum nodes calculate partial tokens $\sigma_i = y_i \cdot w_i \pmod p$ and $T_i = g^{\sigma_i} \pmod P$. The master secret $S$ is never assembled in plaintext memory at any node.
* **Phase 3 (Feldman VSS Verification):** Quorum verifies each token $T_i$ against coefficient commitments $C_0, \dots, C_{t-1}$. Poisoned shares are detected and quarantined before admission decisions are finalized.

---

### 3. UI - Backend - Terminal Synchronization Pipeline

A core requirement of this platform is that **every user interaction triggers real algorithm execution and produces synchronized terminal logging**. There are no dummy buttons, mocked timers, or fabricated responses.

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Swarm Commander
    participant WebUI as Web Operations Dashboard
    participant Server as Threaded Server (serve.py)
    participant Backend as ResearchBackend (backend.py)
    participant Crypto as Cryptographic Engine (crypto/)
    participant Stdout as Physical Terminal Console

    Operator->>WebUI: Click 'Execute Full Mutual Authentication' (Node 102)
    WebUI->>Server: POST /api/authenticate {"uav_id": 102}
    Server->>Backend: authenticate_uav(102)
    Backend->>Stdout: [HH:MM:SS.mmm] [AUTH] Initiating authentication round for UAV 102
    Backend->>Crypto: SwarmPeerNode.generate_partial_token(...)
    Crypto-->>Backend: PartialVerificationToken (T_i, sigma_i)
    Backend->>Stdout: [HH:MM:SS.mmm] [NON-RECON] Quorum computing partial tokens without plaintext secret exposure
    Backend->>Crypto: VerifiableSecretSharing.verify_partial_token(...)
    Crypto-->>Backend: Verification Result: True
    Backend->>Stdout: [HH:MM:SS.mmm] [VSS] Validating incoming shares against public commitments C_0..C_2
    Backend->>Crypto: Compute 256-bit HKDF Session Key
    Crypto-->>Backend: Session Key: 5fc82d7c84d47325...
    Backend->>Stdout: [HH:MM:SS.mmm] [AUTH-OK] Quorum Consensus Admitted Node 102 in 1.70 ms
    Backend->>Stdout: [HH:MM:SS.mmm] [KEY-AGREE] Mutual Session Key: 5fc82d... (256-bit HKDF)
    Backend-->>Server: JSON {success: true, elapsed_ms: 1.70, session_key: "5fc8..."}
    Server-->>WebUI: HTTP 200 OK
    WebUI->>WebUI: Update HUD, draw authentication green beam in 3D airspace, display key
```

#### Terminal Log Format Specification
All backend events conform to a strict, parseable format:
```
[HH:MM:SS.mmm] [SUBSYSTEM] Specific algorithmic event description
```
Valid subsystems:
- `[SETUP]`: Initialization of Mersenne prime field and polynomial commitments.
- `[READY]`: Fleet bootstrap and quorum provisioning confirmation.
- `[API]`: Inbound HTTP request parsing and parameter validation.
- `[AUTH]`: Handshake pass execution and nonce verification.
- `[QUORUM]`: Peer quorum consensus formation and voting.
- `[NON-RECON]`: Homomorphic partial-token calculation ($\sigma_i = y_i \cdot w_i$).
- `[VSS]`: Feldman commitment verification against $g^{a_j} \pmod P$.
- `[QUARANTINE]`: Identification and isolation of malicious or noisy shares.
- `[KEY-AGREE]`: HKDF-SHA256 session key agreement output.
- `[ATTACK]`: Injection of adversarial test vectors.
- `[DEFENSE]`: Cryptographic interception and mitigation log.
- `[BENCHMARK]`: Genuine CPU microsecond execution measurements.

---

### 4. Threat Model & Security Boundaries

The system is evaluated under the standard **Dolev-Yao Threat Model** augmented with physical hardware compromise scenarios:

| Threat Vector | Adversary Capability | Defense Mechanism | Code Verification |
|---|---|---|---|
| **Eavesdropping (Sniffing)** | Attacker captures all transit frames $M_1, M_2, M_3$. | Shares $y_i$ masked with PUF responses ($L_i = y_i \oplus R_i$). Nonces prevent replay. | Mode A & Mode B |
| **Replay Attack** | Attacker replays captured valid $M_1$ frame. | `NonceCache` detects duplicate $N_A$ within window; session aborts immediately. | `test_replay_defense` |
| **Man-in-the-Middle (MitM)** | Attacker flips bits in transit frames. | HMAC-SHA256 with key $H(S)$ fails verification; connection terminated. | `test_mitm_defense` |
| **Cloned / Rogue UAV** | Attacker extracts software code and runs on another drone. | SRAM PUF biometric unique to silicon hardware; incorrect $R_j$ yields corrupted shares. | `test_cloned_puf_defense` |
| **Coordinator Capture** | Attacker physically captures admission leader drone. | Phase 2 Non-Reconstructive aggregation ensures master secret $S$ is never in RAM. | `test_non_reconstructive` |
| **Share Poisoning** | Byzantine / compromised peer injects fake shares. | Phase 3 Feldman VSS verifies $g^{y_i} \equiv \prod C_j^{x_i^j} \pmod P$; node quarantined. | `test_poisoned_share` |
| **Environmental Noise** | High thermal or voltage drift causes PUF bit errors. | 7-sample majority voting + $(t, k)$ polynomial error correction tolerates $\le k-t$ faults. | `test_fault_tolerance` |

---

### 5. Data Flow & State Management

1. **Bootstrap State:**
   - Generated during system startup in `backend.py`.
   - Polynomial coefficients $a_0 = S, a_1, \dots, a_{t-1} \in \mathbb{F}_p$.
   - Public Feldman commitments $C_j = g^{a_j} \pmod P$ stored in memory and shared with all fleet nodes.
2. **Node Provisioning:**
   - UAV enrolled with unique seed, OTP ID, and share $y_i = f(x_i) \pmod p$.
   - UAV independently verifies its own share against $C_j$ before accepting it.
3. **Session Ratcheting:**
   - Each successful authentication triggers one-way forward ratcheting:
     $$\text{State}_{n+1} = \text{HMAC-SHA256}(\text{State}_n, K_{\text{sess}})$$
   - Guarantees backward and forward secrecy across mission life.
