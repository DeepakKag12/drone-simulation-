# 🚁 Drone Swarm with Shamir Secret Sharing Authentication

A PyBullet-based drone swarm simulation with secure authentication using Shamir Secret Sharing for decentralized admission control.

---

## 📋 Table of Contents
1. [Overview](#overview)
2. [How Shamir Secret Sharing Works](#how-shamir-secret-sharing-works)
3. [Authentication Flow](#authentication-flow)
4. [Challenge-Response Protocol](#challenge-response-protocol)
5. [Installation](#installation)
6. [Usage](#usage)
7. [GUI Controls](#gui-controls)
8. [Terminal Output](#terminal-output)

---

## 🎯 Overview

This simulation demonstrates secure drone admission using **Shamir's Secret Sharing** scheme. When a new drone wants to join the swarm:
- It must prove its legitimacy through a cryptographic challenge-response
- The swarm reconstructs a master secret from distributed shares
- The joining drone **NEVER** receives the secret or any shares

### Key Security Properties
- **Decentralized**: No single drone holds the complete secret
- **Threshold-based**: K-of-N drones needed to authenticate
- **Zero-knowledge**: Joining drone proves identity without learning secrets

---

## 🔐 How Shamir Secret Sharing Works

### The Mathematical Foundation

Shamir's Secret Sharing is based on **polynomial interpolation**. A polynomial of degree `K-1` is uniquely determined by `K` points.

#### Step 1: Secret to Polynomial
```
Given:
  - Master Secret: S
  - Threshold: K (minimum shares needed)
  - Total drones: N

Create polynomial:
  f(x) = S + a₁x + a₂x² + ... + aₖ₋₁xᵏ⁻¹  (mod P)

Where:
  - S is the constant term (the secret)
  - a₁, a₂, ... are random coefficients
  - P is a large prime number
```

#### Step 2: Generate Shares
```
Each drone i receives a share:
  Share_i = (i, f(i))

Example with K=3, N=5:
  Drone 1: (1, f(1)) = (1, 847293...)
  Drone 2: (2, f(2)) = (2, 192847...)
  Drone 3: (3, f(3)) = (3, 738291...)
  Drone 4: (4, f(4)) = (4, 928374...)
  Drone 5: (5, f(5)) = (5, 182736...)
```

#### Step 3: Reconstruct Secret
Using **Lagrange Interpolation** with any K shares:
```
S = Σᵢ yᵢ × Lᵢ(0)

Where Lagrange basis polynomial:
  Lᵢ(0) = Π_{j≠i} (0 - xⱼ) / (xᵢ - xⱼ)
```

### Visual Representation
```
        SECRET (S)
            │
    ┌───────┴───────┐
    │   Polynomial  │
    │ f(x) = S + ax │
    └───────┬───────┘
            │
    ┌───────┼───────┐───────┐───────┐
    ▼       ▼       ▼       ▼       ▼
  Share₁  Share₂  Share₃  Share₄  Share₅
  (1,y₁)  (2,y₂)  (3,y₃)  (4,y₄)  (5,y₅)
    │       │       │
    └───────┼───────┘
            │
    ┌───────┴───────┐
    │   Lagrange    │
    │ Interpolation │
    └───────┬───────┘
            │
            ▼
    RECONSTRUCTED S
```

---

## 🔄 Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DRONE AUTHENTICATION FLOW                        │
└─────────────────────────────────────────────────────────────────────┘

    NEW DRONE                          SWARM (Leader + K Drones)
        │                                       │
        │  1. JOIN_REQUEST                      │
        │  (drone_id, certificate, nonce)       │
        ├──────────────────────────────────────►│
        │                                       │
      │                           2. Validate Certificate
        │                           3. Check Blacklist
        │                           4. Select K trusted drones
        │                                       │
        │                           5. Collect K shares:
        │                              ┌────────────────────┐
        │                              │ Drone 1: (1, y₁)   │
        │                              │ Drone 3: (3, y₃)   │
        │                              │ Drone 5: (5, y₅)   │
        │                              └────────────────────┘
        │                                       │
        │                           6. Reconstruct Secret S
        │                              using Lagrange interpolation
        │                                       │
        │                           7. Generate Challenge:
        │                              C = SHA256(S || drone_id || nonce)
        │                                       │
        │  8. CHALLENGE (C)                     │
        │◄──────────────────────────────────────┤
        │                                       │
   9. Sign Challenge                            │
      R = Sign(C, private_key)                  │
        │                                       │
        │  10. RESPONSE (R)                     │
        ├──────────────────────────────────────►│
        │                                       │
        │                           11. Verify Signature
        │                               using public_key
        │                                       │
        │  12. RESULT                           │
        │◄──────────────────────────────────────┤
        │                                       │
   ✅ SUCCESS: Join swarm          OR    ❌ FAILURE: Blacklisted
```

---

## 🎯 Challenge-Response Protocol

### What is the Challenge?
```python
Challenge = SHA256(reconstructed_secret || drone_id || nonce)
```

| Component | Description |
|-----------|-------------|
| `reconstructed_secret` | The master secret reconstructed from K shares |
| `drone_id` | The ID of the joining drone |
| `nonce` | A random 32-character hex string (prevents replay) |

### What is the Response?
```python
Response = SHA256(private_key || challenge)
```

The joining drone signs the challenge with its **private key**, proving:
1. It possesses the correct private key
2. It received the challenge intended for it
3. It's responding to this specific authentication session

### Verification
```python
Expected = SHA256(private_key || challenge)
Valid = (Response == Expected)
```

---

## 💻 Installation

### Requirements
- Python 3.7+
- PyBullet

### Install
```bash
pip install pybullet
```

---

## 🚀 Usage

### Run the Simulation
```bash
cd "c:\Users\deepak kag\OneDrive\Desktop\addition project"
python drone_swarm_pybullet.py
```

---

## 🎮 GUI Controls

| Control | Action |
|---------|--------|
| **➕ Add REAL Drone** | Add a legitimate drone (goes through full authentication) |
| **💀 Add FAKE Drone** | Simulate an attack (RED drone appears, gets rejected, FALLS) |
| **🔧 Cycle Attack Type** | Switch between attack types |
| **➖ Remove Drone** | Remove a drone from the swarm |
| **Camera Distance** | Zoom in/out |
| **Camera Yaw** | Rotate camera horizontally |
| **Camera Pitch** | Rotate camera vertically |

### Attack Types
| Type | Description |
|------|-------------|
| `invalid_signature` | Drone can't sign the challenge correctly |
| `expired_cert` | Drone's certificate has expired |
| `tampered_cert` | Certificate issuer doesn't match |

### Visual Elements
| Element | Color | Description |
|---------|-------|-------------|
| Normal Drones | 🟢 Green | Authenticated swarm members |
| Leader | 🟡 Yellow | Current elected leader |
| Fake Drone | 🔴 Red | Attack drone (falls when rejected) |
| Building | 🔵 Blue Cylinder | Center of orbit |
| Base Station | 🔵 Blue Box | Spawn/landing area |

---

## 📺 Terminal Output

### Share Distribution (on startup)
```
======================================================================
   📦 SHAMIR SECRET SHARE DISTRIBUTION
======================================================================
   Threshold (K): 3 shares needed to reconstruct
   Total Shares (N): 5
   Master Secret: 12839472918374... (hidden)
----------------------------------------------------------------------
   Drone ID     Share Index (x)    Share Value (y)
----------------------------------------------------------------------
   Drone 1      x = 1              y = 847293817263548172...
   Drone 2      x = 2              y = 192847561823746182...
   Drone 3      x = 3              y = 738291827364518273...
   Drone 4      x = 4              y = 928374617283641827...
   Drone 5      x = 5              y = 182736481726384718...
======================================================================
```

### Authentication Success
```
======================================================================
   🔐 SHAMIR SECRET SHARING AUTHENTICATION
   Drone 6 requesting to join swarm
======================================================================

[STEP 1] Checking blacklist...
[STEP 1] ✓ Not blacklisted

[STEP 2] Validating certificate...
[STEP 2] ✓ Certificate valid (Issuer: SwarmCA)

[STEP 3] Selecting 3 trusted drones for secret reconstruction...
[STEP 3] ✓ Selected drones: [1, 3, 5]

   ┌─────────────────────────────────────────────────────────────┐
   │  SHARES USED FOR SECRET RECONSTRUCTION                      │
   ├─────────────────────────────────────────────────────────────┤
   │  Drone 1: Share(x=1, y=84729381726354...)                   │
   │  Drone 3: Share(x=3, y=73829182736451...)                   │
   │  Drone 5: Share(x=5, y=18273648172638...)                   │
   └─────────────────────────────────────────────────────────────┘

[STEP 4] Reconstructing master secret using Lagrange interpolation...
[STEP 4] ✓ Secret reconstructed: 12839472918374... (verified)

[STEP 5] Generating cryptographic challenge...
   Formula: Challenge = SHA256(secret || drone_id || nonce)
   Nonce: 8a7f3c2e1d9b4a6f8c2e1d9b4a6f8c2e
[STEP 5] ✓ Challenge: 7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c...

[STEP 6] Verifying challenge response...
   Drone's signed response: 4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b...
[STEP 6] ✓ Signature verified successfully!

======================================================================
   ✅ AUTHENTICATION SUCCESSFUL
   Drone 6 is APPROVED to join the swarm
======================================================================
```

### Authentication Failure (Fake Drone)
```
🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴
   ⚠️  ATTACK SIMULATION: INVALID_SIGNATURE
🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴

[STEP 6] ❌ FAILED: Invalid signature - challenge response failed
[BLACKLIST] ⛔ Drone 1000: Invalid signature - challenge response failed

🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️
   🛡️  SECURITY: Fake drone 1000 BLOCKED!
   Reason: Invalid signature - challenge response failed
   Blacklisted: 1 drones
🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️🛡️
```

---

## 📁 Project Files

| File | Description |
|------|-------------|
| `drone_swarm_pybullet.py` | Main simulation with Shamir authentication |
| `requirements.txt` | Python dependencies |
| `README.md` | This documentation |

---

## 🔑 Key Security Points

1. **Joining drone NEVER receives the secret** - only a challenge derived from it
2. **K-of-N threshold** - Even if some drones are compromised, the secret is safe
3. **Blacklisting** - Failed authentication attempts result in permanent ban
4. **Nonce prevents replay** - Each authentication session is unique
5. **Certificate validation** - Drones must have valid PKI certificates

---

## 📝 One-Line Summary

> "Shamir Secret Sharing is used internally by the swarm to reconstruct a master authentication secret, enabling secure challenge generation for decentralized admission control without exposing secrets to joining drones."

---

## 👤 Author

Drone Swarm Authentication System with Shamir Secret Sharing
>>>>>>> 22fc59e (Initial commit for drone simulation)
