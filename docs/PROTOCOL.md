# UAV Swarm Threshold Authentication Protocol Specification

## 1. Overview & System Model

This document specifies the mutual authentication and session key agreement protocol implemented across the UAV swarm codebase. The protocol supports dual operational topologies:
1. **Centralized Base Station Mode**: Ground Command Base Station (BS) maintains master enrollment state, issues challenge sets, and ratchets cryptographic state after every session.
2. **Decentralized Quorum Mode**: Infrastructure-less peer swarm executes autonomous admission, non-reconstructive threshold verification, and verifiable secret sharing (VSS) public commitment validation.

### System Entities
- **UAV ($D_i$)**: Resource-constrained aerial node provisioned with an immutable 32-bit hardware identifier in one-time programmable (OTP) memory and an SRAM Physical Unclonable Function (PUF) providing a 320-bit silicon root-of-trust.
- **Base Station ($BS$)**: High-capacity command entity possessing secure non-volatile storage. Maintains challenge-response registers and anti-replay nonce caches.
- **Swarm Peer Node ($P_i$)**: Active swarm drone holding a private Shamir share $(x_i, y_i)$, public VSS coefficient commitments, and PUF hardware.
- **Quorum Coordinator ($QC$)**: Dynamic elected coordinator drone facilitating distributed admission handshakes without holding or learning the master secret $S$.

---

## 2. Mathematical Foundations

### Finite Field Arithmetic ($\mathbb{F}_p$)
All secret sharing, polynomial evaluation, and Lagrange interpolation operations are evaluated over the finite prime field $\mathbb{F}_p$ where $p$ is the Mersenne prime:
$$p = 2^{127} - 1 = 170141183460469231731687303715884105727$$

- Field Addition: $a \oplus_p b = (a + b) \pmod p$
- Field Subtraction: $a \ominus_p b = (a - b + p) \pmod p$
- Field Multiplication: $a \otimes_p b = (a \cdot b) \pmod p$
- Modular Inverse: $a^{-1} \pmod p$ computed via Extended Euclidean Algorithm ($a \cdot a^{-1} \equiv 1 \pmod p$).

### Public Commitment Group ($\mathbb{Z}_P^*$)
For Verifiable Secret Sharing (VSS) and non-reconstructive threshold verification, public commitments are evaluated in the multiplicative group $\mathbb{Z}_P^*$ where $P$ is a safe prime with order $p$:
$$P = 2 \cdot 57 \cdot p + 1 = 19396094914493492417412352623610788052879$$
$$g = 20769187434139310514121985316880384$$
where $g$ has prime order $p$ in $\mathbb{Z}_P^*$ ($g^p \equiv 1 \pmod P$).

### Shamir $(t, k)$ Threshold Scheme
The secret sharing polynomial $f(x) \in \mathbb{F}_p[x]$ has degree $t - 1$:
$$f(x) = S + a_1 x + a_2 x^2 + \dots + a_{t-1} x^{t-1} \pmod p$$
where $S = f(0) \in \mathbb{F}_p^*$ is the master authentication secret, and coefficients $a_1, \dots, a_{t-1} \in \mathbb{F}_p^*$ are uniformly sampled random field elements.

### Barycentric Lagrange Weights
Reconstruction of $f(0) = S$ from any $t$ distinct points $(x_i, y_i)$ is evaluated in $O(t)$ modular multiplications using barycentric weights:
$$S = \sum_{i=0}^{t-1} y_i \cdot w_i \pmod p$$
$$w_i = \prod_{j \neq i, j=0}^{t-1} \frac{-x_j}{x_i - x_j} \pmod p$$

---

## 3. Protocol Message Specifications

### Mode A: Centralized Base Station Workflow

```mermaid
sequenceDiagram
    autonumber
    participant UAV as Applicant UAV (ID, SRAM PUF)
    participant BS as Base Station (Secure Database)

    Note over UAV, BS: PHASE 1: FACTORY ENROLLMENT (Secure Channel)
    BS->>BS: Generate device ID, threshold t, challenge count k
    BS->>BS: Sample secret S in F_p*, build polynomial f(x) of degree t-1
    BS->>BS: Generate k challenges C = {C_1, ..., C_k} (128-bit each)
    BS->>UAV: Provision ID, transfer C
    UAV->>UAV: Write ID to OTP memory
    UAV->>UAV: Evaluate clean PUF responses: R' = {PUF(C_1), ..., PUF(C_k)} (320-bit each)
    UAV->>BS: Transmit R'
    BS->>BS: Map R'_j to x_j in F_p*, compute shares L_j = f(x_j) mod p
    BS->>BS: Compute H(S) = SHA256(S)
    BS->>BS: Store (ID, C, L, H(S)); erase raw R' and S from RAM

    Note over UAV, BS: PHASE 2: MUTUAL AUTHENTICATION (Wireless RF)
    UAV->>UAV: Generate fresh 128-bit nonce N_A
    UAV->>BS: Message 1: [ID, N_A]
    BS->>BS: Validate ID; verify N_A not in Nonce Cache (Anti-replay)
    BS->>BS: Cache N_A; sample fresh 128-bit nonce N_B
    BS->>BS: Compute Q = (N_B || 0^128) XOR H(S)
    BS->>BS: Compute MAC_BS = HMAC-SHA256(H(S), C || H(S) || N_B || L)
    BS->>UAV: Message 2: [C, Q, L, MAC_BS, H(S)]

    UAV->>UAV: Evaluate PUF on C: R_noisy = PUF(C) (subject to bit flips)
    UAV->>UAV: Map R_j to x_j; decode points (x_j, L_j) via Berlekamp-Welch / t-subsets
    UAV->>UAV: Recover candidate secret S* matching SHA256(S*) == H(S)
    UAV->>UAV: Unmask N_B = Q XOR H(S*)
    UAV->>UAV: Verify MAC_BS (Authenticates Base Station to UAV)
    UAV->>UAV: Sample fresh 128-bit nonce N_C; generate fresh challenges C'
    UAV->>UAV: Evaluate fresh PUF responses: R'' = PUF(C')
    UAV->>UAV: Compute P = (N_C || 0^128) XOR H(S*)
    UAV->>UAV: Compute J = (R''_1 || ... || R''_k) XOR PAD(H(S*))
    UAV->>UAV: Compute MAC_UAV = HMAC-SHA256(H(S*), R'' || H(S*) || N_C)
    UAV->>UAV: Derive Session Key Sk = HKDF-SHA256(N_B || N_C || H(S*))
    UAV->>BS: Message 3: [C', J, P, MAC_UAV]

    BS->>BS: Recover N_C = P XOR H(S)
    BS->>BS: Decrypt R'' = J XOR PAD(H(S))
    BS->>BS: Verify MAC_UAV (Authenticates UAV to Base Station)
    BS->>BS: Derive Session Key Sk = HKDF-SHA256(N_B || N_C || H(S))

    Note over BS: PHASE 3: STATE RATCHETING
    BS->>BS: Sample new secret S_new, construct new polynomial f_new(x)
    BS->>BS: Map R''_j to x''_j; evaluate new shares L' = {f_new(x''_j)}
    BS->>BS: Overwrite state: C := C', L := L', H(S) := SHA256(S_new)
    BS->>BS: Securely erase S_new and old CRPs
```

---

### Mode B: Decentralized Quorum Admission Workflow

```mermaid
sequenceDiagram
    autonumber
    participant App as Applicant Drone D_J
    participant QC as Quorum Coordinator
    participant P1 as Quorum Peer 1
    participant P2 as Quorum Peer 2
    participant Pk as Quorum Peer K

    Note over App, Pk: DECENTRALIZED ADMISSION (No Online Base Station)
    App->>QC: M1: [ID_J, N_A]
    QC->>QC: Check N_A not in Nonce Cache; verify ID_J registered
    QC->>P1: Request Partial Challenge & Token
    QC->>P2: Request Partial Challenge & Token
    QC->>Pk: Request Partial Challenge & Token

    P1->>P1: Compute sigma_1 = y_1 * w_1 mod p; T_1 = g^sigma_1 mod P
    P2->>P2: Compute sigma_2 = y_2 * w_2 mod p; T_2 = g^sigma_2 mod P
    Pk->>Pk: Compute sigma_k = y_k * w_k mod p; T_k = g^sigma_k mod P

    P1->>QC: Partial Token T_1, Challenge C_1
    P2->>QC: Partial Token T_2, Challenge C_2
    Pk->>QC: Partial Token T_k, Challenge C_k

    QC->>QC: Phase 3 VSS Check: Verify each T_i matches public commitments C_j
    alt Any token fails VSS
        QC->>QC: Isolate and quarantine malicious peer; reject poisoned share
    end

    QC->>QC: Phase 2 Homomorphic Combination: prod T_i mod P == C_0 == g^S mod P
    QC->>QC: Evaluate shares L for D_J challenges using enrolled PUF profile
    QC->>QC: Sample N_B, compute Q = N_B XOR H(S), compute MAC_Quorum
    QC->>App: M2: [C, Q, L, MAC_Quorum, Commitments]

    App->>App: Evaluate PUF on C; reconstruct S* via Lagrange interpolation
    App->>App: Unmask N_B; verify MAC_Quorum; sample N_C and fresh challenges C'
    App->>App: Evaluate R'' = PUF(C'); compute P, J, MAC_UAV
    App->>App: Derive Session Key Sk = HKDF-SHA256(N_B || N_C || H(S*))
    App->>QC: M3: [C', J, P, MAC_UAV]

    QC->>QC: Recover N_C, decrypt R'', verify MAC_UAV
    QC->>QC: Derive identical Session Key Sk = HKDF-SHA256(N_B || N_C || H(S))
    QC->>App: Admission Granted (Fleet key agreement confirmed)
```

---

## 4. Message Fields & Encoding

| Message | Field | Type / Encoding | Size | Description |
|---|---|---|---|---|
| **$M_1$** | `uav_id` | UInt32 Big-Endian | 4 bytes (32 bits) | Device immutable identifier |
| | `n_a` | Cryptographic random bytes | 16 bytes (128 bits) | Fresh applicant nonce |
| **$M_2$** | `challenges` | Array of 16-byte buffers | $k \times 16$ bytes | Verification challenges $C_1 \dots C_k$ |
| | `q` | Byte buffer | 32 bytes (256 bits) | Masked nonce: $(N_B \parallel 0^{16}) \oplus H(S)$ |
| | `shares_l` | Array of 16-byte Big-Endian ints | $k \times 16$ bytes | Masked polynomial shares $L_j = f(x_j) \pmod p$ |
| | `mac_bs` | HMAC-SHA256 digest | 32 bytes (256 bits) | Tag: $\text{HMAC}(H(S), C \parallel H(S) \parallel N_B \parallel L)$ |
| | `h_s_hint` | SHA-256 digest | 32 bytes (256 bits) | Public validation commitment $H(S)$ |
| | `commitments` | Optional array of $\mathbb{Z}_P^*$ elements | $t \times 16$ bytes | VSS coefficient commitments $C_0 \dots C_{t-1}$ |
| **$M_3$** | `challenges_prime` | Array of 16-byte buffers | $k \times 16$ bytes | Ratchet challenges $C'_1 \dots C'_k$ |
| | `j` | Byte buffer | $k \times 40$ bytes | Masked responses: $(R''_1 \parallel \dots \parallel R''_k) \oplus \text{PAD}(H(S^*))$ |
| | `p` | Byte buffer | 32 bytes (256 bits) | Masked nonce: $(N_C \parallel 0^{16}) \oplus H(S^*)$ |
| | `mac_uav` | HMAC-SHA256 digest | 32 bytes (256 bits) | Tag: $\text{HMAC}(H(S^*), R'' \parallel H(S^*) \parallel N_C)$ |

---

## 5. Architectural Upgrades (Overcoming Inherent Paper Vulnerabilities)

The baseline centralized protocol contains three fundamental architectural weaknesses. The codebase addresses each limitation through sequential upgrades:

### Phase 1: Decentralized Quorum Admission
- **Target Vulnerability:** The baseline protocol requires an online, reachable Ground Base Station. If communication is jammed or out-of-range, joining drones cannot authenticate.
- **Architectural Solution:** An ad-hoc quorum of $K$ neighboring active swarm drones ($K \ge t$) executes the handshake collaboratively. Quorum nodes contribute distributed entropy to challenges and collectively validate admission.
- **Implementation:** `DecentralizedQuorumCoordinator` orchestrates the exchange while preserving infrastructure-less autonomy.

### Phase 2: Non-Reconstructive Threshold Verification
- **Target Vulnerability:** Gathering raw shares $(x_i, y_i)$ at a coordinator exposes the master secret $S$ in plaintext memory. Physical capture of the coordinator exposes the entire fleet's secret.
- **Architectural Solution:** Quorum peers compute masked partial verification scalars locally:
  $$\sigma_i = y_i \cdot w_i \pmod p$$
  $$T_i = g^{\sigma_i} \pmod P$$
  The coordinator combines tokens homomorphically:
  $$\prod_{i \in Q} T_i \equiv g^{\sum \sigma_i} \equiv g^S \equiv C_0 \pmod P$$
  The master secret $S$ is verified against public commitment $C_0$ without ever instantiating $S$ in volatile memory.

### Phase 3: Verifiable Secret Sharing (VSS) Public Commitments
- **Target Vulnerability:** Standard Shamir secret sharing cannot identify corrupted or poisoned shares submitted by compromised peers, causing silent authentication failures.
- **Architectural Solution:** At enrollment, public coefficient commitments are published:
  $$C_j = g^{a_j} \pmod P, \quad j \in \{0, \dots, t-1\}$$
  Incoming shares and tokens are validated on-the-fly:
  $$g^y \equiv \prod_{j=0}^{t-1} (C_j)^{x^j} \pmod P$$
  Invalid tokens are quarantined immediately, isolating compromised nodes without interrupting swarm operations.

```python
# Core Verification Workflow in DecentralizedQuorumCoordinator (crypto/protocol.py)
def verify_quorum_and_admit(self, applicant, quorum_peers, commitments, t):
    if len(quorum_peers) < t or not self.check_nonce_freshness(applicant.nonce_na):
        return False
    quorum_x = [p.x_coord for p in quorum_peers]
    valid_tokens = []
    for peer in quorum_peers:
        token = peer.generate_partial_token(quorum_x) # T_i = g^(y_i * w_i mod p) mod P
        if not self.vss.verify_partial_token(token, commitments, quorum_x):
            self.quarantined_nodes.add(peer.uav_id) # Phase 3: Isolate poisoned share
            continue
        valid_tokens.append(token)
    if len(valid_tokens) < t:
        return False
    # Phase 2: Homomorphic verification without reconstructing secret S
    if self.vss.combine_tokens_homomorphic(valid_tokens[:t]) != commitments[0]:
        return False
    return self.complete_m2_m3_handshake(applicant, quorum_peers[:t])
```

---

## 6. Threat Model & Security Defenses

| Adversarial Attack Vector | Attack Mechanism | Protocol Defense Mechanism | Validated Outcome |
|---|---|---|---|
| **Cloned / Fabricated PUF** | Adversary fabricates drone with incorrect silicon seed | Mismatched PUF responses $R^*$ alter mapped coordinates $x^*$, causing Lagrange reconstruction $f(0)$ to produce $S^* \neq S$. $H(S^*)$ check fails. | **Rejected**: Handshake aborted; secret reconstruction fails. |
| **Replay Attack** | Interception and retransmission of prior valid $M_1$ frame | Verifier (BS or Quorum Coordinator) maintains nonces in an active hash set `nonce_cache`. Replayed $N_A$ triggers immediate alert. | **Quarantined**: Session aborted; replaying device ID isolated. |
| **MitM Message Alteration** | Eavesdropper alters challenge $C$, share $L$, or ciphertext $J$ | HMAC-SHA256 digests $\text{MAC}_{BS}$ and $\text{MAC}_{UAV}$ computed over concatenated payloads using $H(S)$ as secret key. | **Rejected**: Constant-time MAC comparison fails; connection severed. |
| **Hardware Noise Degradation** | Severe environmental thermal/voltage noise ($> k-t$ errors) | Berlekamp-Welch unique radius and combinatorial $t$-subset recovery require at least $t$ valid points. With $< t$ points, no subset matches $H(S)$. | **Rejected**: Safe rejection without false positive admission. |
| **Poisoned Quorum Share** | Compromised peer submits forged partial token during admission | Quorum Coordinator verifies incoming token $T_i$ against public polynomial commitments $C_j$. | **Quarantined**: Compromised peer quarantined; admission proceeds with clean peers. |
| **Unknown Device ID** | Unregistered rogue drone initiates handshake | Device ID checked against enrolled database/swarm registry before processing $M_1$. | **Rejected**: Unknown ID promptly rejected before cryptographic evaluation. |

---

## 7. Ambiguities in Literature Resolved

1. **Polynomial Degree Convention:** The polynomial is defined strictly with degree $t-1$, containing $t$ coefficients. Any $t$ correct points interpolate $S = f(0)$ uniquely.
2. **Finite Field Arithmetic:** Prime field $\mathbb{F}_p$ ($p = 2^{127}-1$) is used instead of integer fractions or unreduced rings, ensuring exact modular multiplicative inverses.
3. **Point Recovery Engine:** Hybrid recovery combines $O(n^3)$ Berlekamp-Welch decoding for errors $e \le \lfloor(k-t)/2\rfloor$ with fallback combinatorial $t$-subset search tolerating up to $k-t$ errors.
4. **Key Derivation Hygiene:** Session keys are derived via standard HKDF-SHA256:
   $$S_k = \text{HKDF-Extract-and-Expand}(\text{IKM}=N_B \parallel N_C \parallel H(S), \text{Info}=\text{"UAV-MutualAuth-SessionKey-v2"}, 256)$$
5. **State Ratcheting:** Complete CRP set consumption with fresh challenge generation and ephemeral secret erasure after every authentication session.
