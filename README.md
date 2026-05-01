---
title: Drone Swarm Simulation
emoji: 🚁
colorFrom: blue
colorTo: purple
sdk: streamlit
pinned: true
app_file: app.py
---

# Drone Swarm Simulation with Shamir Secret Sharing

A 3D PyBullet drone swarm simulation with cryptographic authentication using Shamir Secret Sharing.

## Render (Docker + NoVNC)

Use a Render Web Service with the Dockerfile in this repo.

Steps:
1) Create a new Web Service and connect your GitHub repo.
2) Environment: Docker. Start Command: leave empty.
3) Add env var `PORT=7860`.

Open the service URL in your browser. The NoVNC UI loads at `/` and shows the live PyBullet GUI.

## Controls
- **➕ Add REAL Drone** — Legitimate drone joins (GREEN)
- **💀 Add FAKE Drone** — Attack simulation (RED, falls)
- **🔧 Cycle Attack** — Switch attack type
- **➖ Remove Drone** — Drone leaves swarm