# API_DOCUMENTATION.md
## Cryptographic Backend REST & Server-Sent Events (SSE) Specification

**Project:** Autonomous UAV Swarm Mutual Authentication & State-Ratcheted Key Agreement  
**Group:** Group 24 (Deepak Kag, Y Sri Harsha Raju, K Hemanth)  
**Host Binding:** `http://127.0.0.1:8000` (IPv4 loopback)  
**Encoding:** UTF-8 | Content-Type: `application/json` (REST) / `text/event-stream` (SSE)  

---

### 1. Overview & Connection Architecture

The application backend exposes a lightweight, non-blocking HTTP/1.1 REST API backed by an asynchronous Server-Sent Events (`/api/events`) channel. Every API request executes real mathematical operations in the Python cryptographic core and emits real-time events to both stdout and connected Web UI clients.

```
                      +-----------------------------+
                      |   Web Operations Center     |
                      +-----------------------------+
                        |                         ^
        HTTP REST (JSON)|                         | SSE Stream
                        v                         | (/api/events)
                      +-----------------------------+
                      | ResearchAPIHandler (serve)  |
                      +-----------------------------+
                                     |
                                     v
                      +-----------------------------+
                      |  ResearchBackend Core       |
                      |  - p = 2^127 - 1 Field      |
                      |  - 320-bit SRAM PUF Model   |
                      |  - Shamir (t, k) Threshold  |
                      |  - Feldman VSS Commitments  |
                      +-----------------------------+
```

---

### 2. Endpoint Index

| Method | Endpoint | Description | Payloads |
|---|---|---|---|
| `GET` | `/api/status` | Retrieve live fleet status, topology, and VSS commitments | None |
| `GET` | `/api/events` | Stream live server execution events to terminal HUD | SSE Stream |
| `POST` | `/api/configure` | Dynamically update threshold parameters and topology mode | JSON Config |
| `POST` | `/api/enroll` | Provision and verify a new applicant UAV node | JSON Empty |
| `POST` | `/api/authenticate` | Execute full mutual authentication round for a target node | JSON UAV ID |
| `POST` | `/api/attack` | Trigger genuine cryptographic attack vectors and defenses | JSON Attack Type |
| `POST` | `/api/benchmark` | Execute genuine CPU micro-benchmarks on core primitives | JSON Empty |
| `GET` | `/api/export/json` | Download complete cryptographic benchmark audit report | JSON Download |
| `GET` | `/api/export/csv` | Download comparative evaluation table in CSV format | CSV Download |

---

### 3. Detailed Endpoint Specifications

#### 3.1 GET `/api/status`
Retrieves the real-time operational status of the swarm, including current topology mode, threshold parameters, active fleet roster, and Feldman public commitments.

* **Request Example:**
  ```bash
  curl -X GET http://127.0.0.1:8000/api/status
  ```

* **Success Response (HTTP 200 OK):**
  ```json
  {
    "mode": "DECENTRALIZED_QUORUM",
    "t": 3,
    "k": 6,
    "noise_rate": 0.02,
    "majority_votes": 7,
    "fleet": [
      {
        "id": 101,
        "x": "0x000e99",
        "role": "QUORUM_PEER",
        "is_quarantined": false,
        "status": "AUTHENTICATED"
      },
      {
        "id": 102,
        "x": "0x000ebe",
        "role": "QUORUM_PEER",
        "is_quarantined": false,
        "status": "AUTHENTICATED"
      }
    ],
    "fleet_count": 5,
    "quarantine_count": 0,
    "session_key": "437b707be3f6fdd63a2e6f637ccc0f1c34a17...",
    "commitments": [
      "0x7f3faab953565d5974ac4130f15aeb74a",
      "0x26486675a894c265fe6f5980bdd2dbd682",
      "0xf186660bbfcc17bb77da59f41fbfd9ce6"
    ],
    "last_correct_indices": [0, 1, 2, 3, 4, 5],
    "last_admission_ms": 1.70,
    "bs_status": "STANDBY (QUORUM)"
  }
  ```

---

#### 3.2 GET `/api/events`
Opens a persistent Server-Sent Events (SSE) stream. Whenever the backend logs an event, it is immediately serialized and dispatched over this stream.

* **Headers:**
  - `Content-Type: text/event-stream`
  - `Cache-Control: no-cache`
  - `Connection: keep-alive`

* **Stream Event Format:**
  ```text
  data: {"time": "01:14:24.744", "subsystem": "AUTH", "level": "step", "message": "Initiating authentication round for UAV 102 [Mode: DECENTRALIZED_QUORUM]"}

  data: {"time": "01:14:24.746", "subsystem": "AUTH-OK", "level": "success", "message": "Quorum Consensus Admitted Node 102 in 1.70 ms"}
  ```

---

#### 3.3 POST `/api/configure`
Dynamically adjusts the cryptographic engine parameters.

* **Request Example:**
  ```bash
  curl -X POST http://127.0.0.1:8000/api/configure \
    -H "Content-Type: application/json" \
    -d '{
      "t": 3,
      "k": 6,
      "noise_rate": 0.05,
      "majority_votes": 7,
      "mode": "DECENTRALIZED_QUORUM"
    }'
  ```

* **Success Response (HTTP 200 OK):**
  ```json
  {
    "success": true,
    "mode": "DECENTRALIZED_QUORUM",
    "t": 3,
    "k": 6,
    "noise_rate": 0.05,
    "majority_votes": 7
  }
  ```

---

#### 3.4 POST `/api/enroll`
Provisions a new applicant UAV. The node initializes a new 320-bit SRAM PUF fingerprint, receives a Shamir share, verifies the share against public commitments $C_j$, and completes an initial admittance authentication.

* **Request Example:**
  ```bash
  curl -X POST http://127.0.0.1:8000/api/enroll \
    -H "Content-Type: application/json" \
    -d '{}'
  ```

* **Success Response (HTTP 200 OK):**
  ```json
  {
    "uav_id": 106,
    "x": "0x000f52",
    "role": "QUORUM_PEER",
    "auth": {
      "success": true,
      "uav_id": 106,
      "session_key": "21654bbd06f080ccf9b3d224f15b777c...",
      "elapsed_ms": 1.83,
      "correct_indices": [0, 1, 2, 3, 4, 5],
      "quarantined_peers": []
    }
  }
  ```

---

#### 3.5 POST `/api/authenticate`
Executes an authentication round for an existing UAV node using the currently active topology mode.

* **Request Example:**
  ```bash
  curl -X POST http://127.0.0.1:8000/api/authenticate \
    -H "Content-Type: application/json" \
    -d '{"uav_id": 102}'
  ```

* **Success Response (HTTP 200 OK):**
  ```json
  {
    "success": true,
    "uav_id": 102,
    "session_key": "5fc82d7c84d47325f82564f3f49ec1374a2b918...",
    "elapsed_ms": 1.70,
    "correct_indices": [0, 1, 2, 3, 4, 5],
    "quarantined_peers": []
  }
  ```

---

#### 3.6 POST `/api/attack`
Executes an actual adversarial test vector against the live mathematical algorithm to verify defense mechanisms.

* **Supported Attack Vectors:**
  - `"poisoned_share"`: A quorum peer corrupts its discrete-log share. Feldman VSS detects and isolates the node.
  - `"mitm"`: Inverts bits in transit HMAC authentication tags.
  - `"replay"`: Replays an observed $M_1$ nonce frame. Nonce cache rejects duplicate.
  - `"clone"`: Replaces hardware SRAM PUF with a cloned software instance. Mathematical reconstruction fails.
  - `"excess_noise"`: Induces environmental error rate exceeding fault margin $(> k-t)$. Reconstruction safely aborts.

* **Request Example:**
  ```bash
  curl -X POST http://127.0.0.1:8000/api/attack \
    -H "Content-Type: application/json" \
    -d '{"attack_type": "poisoned_share"}'
  ```

* **Success Defense Response (HTTP 200 OK):**
  ```json
  {
    "success": false,
    "reason": "Poisoned share detected from peer(s) [102]! VSS verification rejected invalid token",
    "quarantined_peers": [102],
    "expected_failure": true
  }
  ```

---

#### 3.7 POST `/api/benchmark`
Runs CPU microsecond profiling across all cryptographic primitives on the host processor and computes genuine Bit Error Rate (BER) reliability curves.

* **Request Example:**
  ```bash
  curl -X POST http://127.0.0.1:8000/api/benchmark \
    -H "Content-Type: application/json" \
    -d '{}'
  ```

* **Success Response (HTTP 200 OK):**
  ```json
  {
    "primitives_us": {
      "xor": 1.84,
      "hash": 0.50,
      "hmac": 1.78,
      "puf": 1133.48,
      "barycentric": 0.83
    },
    "noise_curve": [
      {"ber": "0%", "majority_rate": 100.0, "raw_rate": 100.0},
      {"ber": "1%", "majority_rate": 100.0, "raw_rate": 96.0},
      {"ber": "2%", "majority_rate": 100.0, "raw_rate": 92.0},
      {"ber": "5%", "majority_rate": 100.0, "raw_rate": 80.0},
      {"ber": "8%", "majority_rate": 96.0, "raw_rate": 64.0},
      {"ber": "10%", "majority_rate": 88.0, "raw_rate": 48.0}
    ],
    "security_vs_time": [
      {"label": "25% (t=2)", "time_us": 3.0},
      {"label": "50% (t=4)", "time_us": 3.5},
      {"label": "75% (t=6)", "time_us": 4.2},
      {"label": "100% (t=8)", "time_us": 5.1}
    ],
    "specs": {
      "comm_cost_bits": 1792,
      "storage_cost_bits": 352,
      "micro_time_us": 450,
      "rpi_time_us": 207,
      "measured_time_ms": 1.70,
      "far_rate": "0.0000%"
    }
  }
  ```

---

#### 3.8 GET `/api/export/json` and GET `/api/export/csv`
Downloads research evaluation datasets for academic publication and thesis reporting.

* **JSON Export Example:**
  ```bash
  curl -X GET http://127.0.0.1:8000/api/export/json -o experiment_results.json
  ```

* **CSV Export Example:**
  ```bash
  curl -X GET http://127.0.0.1:8000/api/export/csv -o benchmark_comparison.csv
  ```
