# SETUP.md
## Installation, Launch & Execution Guide

**Project:** Autonomous UAV Swarm Mutual Authentication & State-Ratcheted Key Agreement  
**Group:** Group 24 (Deepak Kag, Y Sri Harsha Raju, K Hemanth)  
**Supported Platforms:** Windows 10/11, Ubuntu/Debian Linux, macOS  
**Runtime:** Python 3.10+ (Standard Library only - zero pip installations required)  

---

### 1. System Requirements & Prerequisites

- **Python:** Python 3.10, 3.11, or 3.12 (standard library `hashlib`, `hmac`, `secrets`, `math`, `dataclasses`, `socketserver`, `http.server` used exclusively).
- **Web Browser:** Any modern evergreen browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Apple Safari) supporting ES2022 JavaScript, WebGL (Three.js), and CSS Grid.
- **Node.js (Optional):** Node.js 18.0.0+ if executing the independent JavaScript test suite (`test_protocol.mjs`).

---

### 2. Quick-Start Execution Methods

#### Method 1: Full Interactive System with Real Research Backend (Recommended for Demonstration)
Launches the multi-threaded HTTP/SSE server and automatically opens the tactical dashboard in your default browser:

```bash
# Windows / Linux / macOS
python serve.py 8000
```
*Alternatively on Windows, double-click [`run_web.bat`](file:///c:/Users/deepak%20kag/OneDrive/Desktop/addition%20project/run_web.bat).*

**Expected Terminal Output:**
```
==============================================================================
   UAV SWARM OPERATIONS WORKBENCH & REAL RESEARCH BACKEND
   Cryptographic Engine: Mersenne Prime F_p (p = 2^127 - 1) | SRAM PUF
   Protocols: Mode A (Centralized BS) & Mode B (Decentralized Quorum + VSS)
==============================================================================
   Root Directory: .../shamir-web

   >>> CLICK TO OPEN IN BROWSER:
       http://localhost:8000/
       http://127.0.0.1:8000/

   [LIVE TERMINAL ACTIVE] All UI actions execute real algorithms and log here in real time.
   (Press Ctrl+C in this terminal to stop)
==============================================================================
```

Once the browser opens, every button clicked in the interface (e.g. *Execute Full Mutual Authentication*, *Deploy & Enroll UAV*, *Trigger Share Poisoning Attack*, *Run Live Micro-Benchmarks*) immediately logs real cryptographic execution to this terminal window!

---

#### Method 2: Comprehensive Protocol Test Suite (Python)
Executes all 17 automated verification test suites covering finite field mathematics, Shamir secret reconstruction, PUF majority voting, Feldman VSS public commitments, non-reconstructive homomorphic token aggregation, and adversarial defense vectors:

```bash
python test_protocol.py
```

**Expected Result:**
```
============================================================================
   [PASS] ALL 17 TEST SUITES PASSED SUCCESSFULLY in ~77 ms!
============================================================================
```

---

#### Method 3: REST & SSE API Integration Test Suite
Verifies all 11 REST API endpoints and Server-Sent Events integration by launching an in-process server instance and evaluating live cryptographic responses:

```bash
python test_api.py
```

**Expected Result:**
```
=======================================================
>>> ALL 11 API ROUTES EXECUTE REAL RESEARCH LOGIC! <<<
=======================================================
```

---

#### Method 4: Headless JavaScript Cryptographic Test Suite (Node.js)
Verifies that the client-side cryptographic engine matches the Python backend field arithmetic and protocol validation:

```bash
node --test shamir-web/test_protocol.mjs
```

**Expected Result:**
```
ℹ tests 12
ℹ pass 12
ℹ fail 0
ℹ duration_ms ~137
```

---

#### Method 5: Interactive Simulation CLI
Runs the text-based cryptographic demonstration console:

```bash
python simulation.py
```
or
```bash
python main.py
```

---

### 3. Port Configuration & Troubleshooting

#### Changing the Web Server Port
If port 8000 is occupied by another local service, specify any free port as a command-line argument:
```bash
python serve.py 8080
```
`serve.py` also contains automatic port fallback logic: if port 8000 is busy, it attempts 8080, 8081, and 8888 automatically.

#### Testing SSE Live Stream from Terminal
To verify that real-time terminal replication is actively streaming events:
```bash
curl -N http://127.0.0.1:8000/api/events
```

#### Firewall Notice
`serve.py` binds exclusively to the local loopback interface (`127.0.0.1`). It does not open external public ports and does not require administrative privileges.
