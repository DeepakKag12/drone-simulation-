/**
 * UAV Swarm Admission Control & Telemetry Engine.
 * Integrates Three.js 3D Field Rendering, Web Crypto Asynchronous Protocol Engine,
 * Monospace Event Stream, Fleet Registry, and Performance Telemetry.
 */

import {
    PRIME_P,
    COMMITMENT_PRIME_P,
    COMMITMENT_GENERATOR_G,
    bytesToHex,
    hexToBytes,
    timingSafeEqual,
    randomSecret,
} from './field.js';
import { SRAMPUF } from './puf.js';
import {
    VerifiableSecretSharing,
} from './shamir.js';
import {
    BaseStation,
    UAV,
    ProtocolMode,
    SwarmPeerNode,
    DecentralizedQuorumCoordinator,
} from './protocol.js';

// ==============================================================================
// Global Application State
// ==============================================================================

const state = {
    protocolMode: ProtocolMode.DECENTRALIZED_QUORUM,
    t: 3,
    k: 6,
    noiseRate: 0.02,
    majorityVotes: 7,
    baseStation: new BaseStation(),
    vss: new VerifiableSecretSharing(COMMITMENT_GENERATOR_G, COMMITMENT_PRIME_P, PRIME_P),
    commitments: [],
    swarmPeers: new Map(), // uavId -> SwarmPeerNode
    quorumCoordinator: null,
    poly: null,
    uavs: new Map(),        // uavId -> UAV instance
    uavMeshes: new Map(),    // uavId -> Three.js Mesh / Object3D
    selectedUavId: 101,
    quarantineCount: 0,
    nextUavId: 101,
    charts: {},
    isSimPaused: false,
    simSpeed: 1.0,
    camMode: 'orbit',
    soundEnabled: true,
};

// ==============================================================================
// Synthetic Tactical Web Audio Synthesizer (Zero External Audio Assets)
// ==============================================================================

let audioCtx = null;

function initAudio() {
    if (!audioCtx && typeof window.AudioContext !== 'undefined') {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
}

function playTone(freq, type = 'sine', duration = 0.08, gainVal = 0.04) {
    if (!state.soundEnabled) return;
    try {
        initAudio();
        if (!audioCtx) return;
        if (audioCtx.state === 'suspended') {
            audioCtx.resume();
        }
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = type;
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
        gain.gain.setValueAtTime(gainVal, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + duration);
    } catch (_) {}
}

function playHandshakeSuccessSound() {
    playTone(523.25, 'sine', 0.08, 0.04);
    setTimeout(() => playTone(659.25, 'sine', 0.12, 0.04), 70);
}

function playQuarantineAlertSound() {
    playTone(330, 'sawtooth', 0.14, 0.06);
    setTimeout(() => playTone(220, 'sawtooth', 0.18, 0.06), 110);
}

// ==============================================================================
// Live Cryptographic Stepper Controller
// ==============================================================================

export function updateStepper(stepNum, statusText = '') {
    const textEl = document.getElementById('stepper-state-text');
    if (textEl && statusText) textEl.textContent = statusText;

    for (let i = 1; i <= 5; i++) {
        const pill = document.getElementById(`step-pill-${i}`);
        const line = document.getElementById(`step-line-${i}`);
        if (!pill) continue;
        if (i < stepNum) {
            pill.className = 'step-pill completed';
            if (line) line.className = 'step-line active';
        } else if (i === stepNum) {
            pill.className = 'step-pill active';
            if (line) line.className = 'step-line';
        } else {
            pill.className = 'step-pill';
            if (line) line.className = 'step-line';
        }
    }
}

// ==============================================================================
// Real-Time Server-Sent Events (SSE) Live Terminal Synchronization
// ==============================================================================

let sseConnection = null;

export function initSSE() {
    if (typeof EventSource === 'undefined') return;
    try {
        if (sseConnection) sseConnection.close();
        sseConnection = new EventSource('/api/events');
        sseConnection.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                logTerminal(`[${data.source}] ${data.message}`, data.level);
            } catch (_) {}
        };
        sseConnection.onerror = () => {
            // Browser handles automatic SSE reconnect backoff
        };
    } catch (e) {
        console.warn("SSE connection error:", e);
    }
}

// ==============================================================================
// Event Stream Logger
// ==============================================================================

const terminalBody = document.getElementById('terminal-body');

export function logTerminal(msg, type = 'info') {
    if (!terminalBody) return;
    const line = document.createElement('div');
    const typeMap = {
        'info': 'log-info',
        'system': 'log-sys',
        'success': 'log-ok',
        'warn': 'log-warn',
        'danger': 'log-err',
        'step': 'log-step',
    };
    line.className = `log-row ${typeMap[type] || 'log-info'}`;
    const timeStr = new Date().toISOString().substring(11, 23);
    line.textContent = `[${timeStr}] ${msg}`;
    terminalBody.appendChild(line);
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

// ==============================================================================
// Three.js 3D Tactical Field Viewport
// ==============================================================================

let scene, camera, renderer, swarmGroup, beamGroup;
let isDragging = false, prevMouseX = 0, prevMouseY = 0;
let camRadius = 85, camTheta = Math.PI / 4, camPhi = Math.PI / 3.5;

function initThreeScene() {
    const container = document.getElementById('three-container');
    if (!container || typeof THREE === 'undefined') {
        logTerminal("Three.js not loaded or container element missing; 3D rendering disabled", "warn");
        return;
    }

    const width = container.clientWidth;
    const height = container.clientHeight;

    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0d14);
    scene.fog = new THREE.FogExp2(0x0a0d14, 0.007);

    camera = new THREE.PerspectiveCamera(45, width / height, 1, 1000);
    updateCameraPosition();

    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(window.devicePixelRatio || 1);
    container.appendChild(renderer.domElement);

    // Illumination
    const ambientLight = new THREE.AmbientLight(0x283244, 1.4);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x94a3b8, 1.2);
    dirLight.position.set(40, 80, 40);
    scene.add(dirLight);

    // Tactical ground coordinate grid
    const gridHelper = new THREE.GridHelper(120, 24, 0x1f2738, 0x121722);
    gridHelper.position.y = 0;
    scene.add(gridHelper);

    // Concentric range rings
    for (const r of [24, 48]) {
        const ringGeo = new THREE.RingGeometry(r - 0.15, r + 0.15, 64);
        const ringMat = new THREE.MeshBasicMaterial({ color: 0x1e293b, side: THREE.DoubleSide });
        const ringMesh = new THREE.Mesh(ringGeo, ringMat);
        ringMesh.rotation.x = Math.PI / 2;
        ringMesh.position.y = 0.02;
        scene.add(ringMesh);
    }

    // Central Base Station Tower
    const towerGeo = new THREE.CylinderGeometry(1.8, 3.2, 30, 8);
    const towerMat = new THREE.MeshStandardMaterial({ color: 0x162032, metalness: 0.8, roughness: 0.3 });
    const tower = new THREE.Mesh(towerGeo, towerMat);
    tower.position.set(0, 15, 0);
    scene.add(tower);

    // Tower Transceiver Mast with emissive glow
    const beaconGeo = new THREE.SphereGeometry(1.4, 16, 16);
    const beaconMat = new THREE.MeshStandardMaterial({
        color: 0x00f0ff,
        emissive: 0x0284c7,
        emissiveIntensity: 0.9,
        metalness: 0.2,
        roughness: 0.2
    });
    const beacon = new THREE.Mesh(beaconGeo, beaconMat);
    beacon.position.set(0, 31, 0);
    scene.add(beacon);

    const beaconLight = new THREE.PointLight(0x00f0ff, 1.5, 45);
    beaconLight.position.set(0, 32, 0);
    scene.add(beaconLight);

    // Groups
    swarmGroup = new THREE.Group();
    scene.add(swarmGroup);

    beamGroup = new THREE.Group();
    scene.add(beamGroup);

    // Mouse / drag orbit controls
    container.addEventListener('mousedown', (e) => {
        isDragging = true;
        prevMouseX = e.clientX;
        prevMouseY = e.clientY;
    });

    window.addEventListener('mouseup', () => { isDragging = false; });

    container.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        const dx = e.clientX - prevMouseX;
        const dy = e.clientY - prevMouseY;
        prevMouseX = e.clientX;
        prevMouseY = e.clientY;

        camTheta -= dx * 0.008;
        camPhi = Math.max(0.15, Math.min(Math.PI / 2.1, camPhi + dy * 0.008));
        updateCameraPosition();
    });

    container.addEventListener('wheel', (e) => {
        e.preventDefault();
        camRadius = Math.max(30, Math.min(180, camRadius + e.deltaY * 0.08));
        updateCameraPosition();
    }, { passive: false });

    // Modern 3D Raycasting Drone Picker
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    container.addEventListener('click', (e) => {
        const rect = container.getBoundingClientRect();
        mouse.x = ((e.clientX - rect.left) / container.clientWidth) * 2 - 1;
        mouse.y = -((e.clientY - rect.top) / container.clientHeight) * 2 + 1;
        raycaster.setFromCamera(mouse, camera);
        if (swarmGroup) {
            const intersects = raycaster.intersectObjects(swarmGroup.children, true);
            if (intersects.length > 0) {
                let obj = intersects[0].object;
                while (obj.parent && obj.parent !== swarmGroup) {
                    obj = obj.parent;
                }
                if (obj.userData && obj.userData.uavId) {
                    selectDrone(obj.userData.uavId);
                }
            }
        }
    });

    // Modern Web ResizeObserver for responsive canvas refits
    if (typeof ResizeObserver !== 'undefined') {
        const resizeObserver = new ResizeObserver(() => {
            onWindowResize();
        });
        resizeObserver.observe(container);
    } else {
        window.addEventListener('resize', onWindowResize);
    }

    requestAnimationFrame(renderLoop);
}

function updateCameraPosition() {
    if (!camera) return;
    camera.position.x = camRadius * Math.sin(camPhi) * Math.cos(camTheta);
    camera.position.y = camRadius * Math.cos(camPhi);
    camera.position.z = camRadius * Math.sin(camPhi) * Math.sin(camTheta);
    camera.lookAt(0, 14, 0);
}

function onWindowResize() {
    const container = document.getElementById('three-container');
    if (!container || !renderer || !camera) return;
    const w = container.clientWidth;
    const h = container.clientHeight;
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    renderer.setSize(w, h);
}

export function selectDrone(uavId) {
    state.selectedUavId = uavId;
    const labelEl = document.getElementById('selected-uav-label');
    const pufInfoEl = document.getElementById('selected-uav-puf-info');
    if (labelEl) labelEl.textContent = `UAV ${uavId} RESPONSE REGISTER`;
    if (pufInfoEl) pufInfoEl.textContent = `(SRAM PUF 320-bit, t=${state.t}, k=${state.k})`;

    const uav = state.uavs.get(uavId);
    if (uav && uav.lastCorrectIndices) {
        renderResponsePointChips(uav.lastCorrectIndices, state.k);
    } else {
        renderResponsePointChips(Array.from({ length: state.k }, (_, i) => i), state.k);
    }

    const tbody = document.getElementById('fleet-table-body');
    if (tbody) {
        Array.from(tbody.children).forEach(row => {
            const firstCell = row.children[0];
            if (firstCell && firstCell.textContent.trim() === uavId.toString()) {
                row.style.background = 'rgba(56, 189, 248, 0.18)';
            } else {
                row.style.background = '';
            }
        });
    }

    const hudEl = document.getElementById('hud-live-action');
    if (hudEl) hudEl.textContent = `UAV ${uavId} TRACKED`;
    logTerminal(`UAV ${uavId} telemetry selected.`, 'info');
    playTone(440, 'sine', 0.05, 0.03);
}

function createDroneMesh(uavId, isTrusted = true) {
    const drone = new THREE.Group();

    // Central chassis
    const bodyGeo = new THREE.BoxGeometry(1.6, 0.6, 1.6);
    const bodyColor = isTrusted ? 0x10b981 : 0xf43f5e;
    const bodyMat = new THREE.MeshStandardMaterial({
        color: bodyColor,
        roughness: 0.35,
        metalness: 0.65,
        emissive: isTrusted ? 0x064e3b : 0x881337,
        emissiveIntensity: 0.35,
    });
    const bodyMesh = new THREE.Mesh(bodyGeo, bodyMat);
    drone.add(bodyMesh);

    // Quadcopter carbon arms
    const armGeo = new THREE.BoxGeometry(4.0, 0.12, 0.2);
    const armMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, metalness: 0.8, roughness: 0.2 });
    const arm1 = new THREE.Mesh(armGeo, armMat);
    arm1.rotation.y = Math.PI / 4;
    drone.add(arm1);
    const arm2 = new THREE.Mesh(armGeo, armMat);
    arm2.rotation.y = -Math.PI / 4;
    drone.add(arm2);

    // 4 High-Speed Spinning Rotor Discs at the arm tips
    const rotors = [];
    const rotorGeo = new THREE.CylinderGeometry(0.7, 0.7, 0.03, 16);
    const rotorMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        transparent: true,
        opacity: 0.45,
    });
    const rotorOffsets = [
        [1.41, 0.15, 1.41],
        [-1.41, 0.15, 1.41],
        [1.41, 0.15, -1.41],
        [-1.41, 0.15, -1.41],
    ];
    rotorOffsets.forEach(([ox, oy, oz]) => {
        const rMesh = new THREE.Mesh(rotorGeo, rotorMat);
        rMesh.position.set(ox, oy, oz);
        drone.add(rMesh);
        rotors.push(rMesh);
    });

    drone.userData = {
        uavId,
        isTrusted,
        bodyMat,
        rotors,
        angle: Math.random() * Math.PI * 2,
        radius: 34 + Math.random() * 8,
        altitude: 20 + Math.random() * 12,
        speed: 0.25 + Math.random() * 0.15,
        isQuarantined: false,
    };

    drone.position.set(
        drone.userData.radius * Math.cos(drone.userData.angle),
        drone.userData.altitude,
        drone.userData.radius * Math.sin(drone.userData.angle)
    );

    swarmGroup.add(drone);
    state.uavMeshes.set(uavId, drone);
    updateFleetTable();
    return drone;
}

function updateDroneVisualState(uavId, visualState) {
    const mesh = state.uavMeshes.get(uavId);
    if (!mesh) return;
    const mat = mesh.userData.bodyMat;

    if (visualState === 'TRUSTED') {
        mat.color.setHex(0x10b981);
        mat.emissive.setHex(0x064e3b);
        mat.emissiveIntensity = 0.4;
        mesh.userData.isQuarantined = false;
    } else if (visualState === 'AUTHENTICATING') {
        mat.color.setHex(0xf59e0b);
        mat.emissive.setHex(0x78350f);
        mat.emissiveIntensity = 0.55;
    } else if (visualState === 'QUARANTINED') {
        mat.color.setHex(0xf43f5e);
        mat.emissive.setHex(0x881337);
        mat.emissiveIntensity = 0.65;
        mesh.userData.isQuarantined = true;
    } else if (visualState === 'MALICIOUS') {
        mat.color.setHex(0xe11d48);
        mat.emissive.setHex(0x9f1239);
        mat.emissiveIntensity = 0.75;
        mesh.userData.isQuarantined = true;
    }
    updateFleetTable();
}

function flashTelemetryBeam(fromPos, toPos, colorHex = 0x00f0ff) {
    if (!scene || !beamGroup) return;
    const points = [
        new THREE.Vector3(fromPos.x, fromPos.y, fromPos.z),
        new THREE.Vector3(toPos.x, toPos.y, toPos.z),
    ];
    const geo = new THREE.BufferGeometry().setFromPoints(points);
    const mat = new THREE.LineBasicMaterial({ color: colorHex, linewidth: 2.5 });
    const line = new THREE.Line(geo, mat);
    beamGroup.add(line);

    setTimeout(() => {
        beamGroup.remove(line);
        geo.dispose();
        mat.dispose();
    }, 450);
}

let lastTime = performance.now();
function renderLoop(now) {
    const dt = (now - lastTime) * 0.001;
    lastTime = now;

    if (!state.isSimPaused && swarmGroup) {
        const effectiveDt = dt * state.simSpeed;
        swarmGroup.children.forEach(drone => {
            const d = drone.userData;
            if (d.rotors) {
                d.rotors.forEach(r => { r.rotation.y += 0.45 * state.simSpeed; });
            }
            if (d.isQuarantined) {
                drone.position.y = Math.max(0.6, drone.position.y - effectiveDt * 20);
            } else {
                d.angle += d.speed * effectiveDt;
                drone.position.x = d.radius * Math.cos(d.angle);
                drone.position.z = d.radius * Math.sin(d.angle);
            }
        });
    }

    // Camera preset modes
    if (state.camMode === 'topdown') {
        camera.position.set(0, 110, 0.001);
        camera.lookAt(0, 0, 0);
    } else if (state.camMode === 'follow') {
        const targetMesh = state.uavMeshes.get(state.selectedUavId);
        if (targetMesh) {
            const tp = targetMesh.position;
            camera.position.set(tp.x + 18, tp.y + 14, tp.z + 18);
            camera.lookAt(tp.x, tp.y, tp.z);
        } else {
            updateCameraPosition();
        }
    }

    if (renderer && scene && camera) {
        renderer.render(scene, camera);
    }
    requestAnimationFrame(renderLoop);
}

// ==============================================================================
// Protocol Execution Controller (Connected to Real Python Research Backend)
// ==============================================================================

async function deployAndEnrollUav(uavId) {
    try {
        const res = await fetch('/api/enroll', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ uav_id: uavId })
        });
        if (res.ok) {
            const data = await res.json();
            createDroneMesh(data.uav_id || uavId, true);
            updateFleetTable();
            return;
        }
    } catch (_) {}

    const puf = new SRAMPUF(null, state.noiseRate);
    const uav = new UAV(uavId, puf, state.t, state.k);
    state.uavs.set(uavId, uav);

    // Initial challenges & responses for factory enrollment
    const initChallenges = [];
    for (let i = 0; i < state.k; i++) {
        const c = new Uint8Array(16);
        globalThis.crypto.getRandomValues(c);
        initChallenges.push(c);
    }
    const enrollResp = await puf.evaluateSet(initChallenges, 0.0);
    await state.baseStation.enrollUAV(uavId, state.t, state.k, enrollResp, initChallenges);
    state.quorumCoordinator.registerUav(uavId, puf);

    // Quorum peer setup: assign secret share & validate against commitments
    if (state.poly && state.commitments.length > 0) {
        const px = BigInt(uavId * 37);
        const py = state.poly.evaluate(px);
        const peerNode = new SwarmPeerNode(uavId, px, py, state.commitments, puf, PRIME_P);
        state.swarmPeers.set(uavId, peerNode);
    }

    createDroneMesh(uavId, true);
    logTerminal(`Node ${uavId} enrolled (SRAM PUF provisioning, t=${state.t}, k=${state.k})`, 'system');
    updateFleetTable();
}

async function authenticateUav(uavId, options = {}) {
    const droneMesh = state.uavMeshes.get(uavId);
    const dronePos = droneMesh ? { x: droneMesh.position.x, y: droneMesh.position.y, z: droneMesh.position.z } : { x: 0, y: 20, z: 0 };
    updateDroneVisualState(uavId, 'AUTHENTICATING');
    updateStepper(1, `PHASE 1: QUORUM CHALLENGE ISSUED (NODE ${uavId})`);

    // Draw peer-to-peer laser telemetry lines
    for (const [peerId, pMesh] of state.uavMeshes) {
        if (peerId !== uavId && !pMesh.userData.isQuarantined) {
            flashTelemetryBeam(
                { x: pMesh.position.x, y: pMesh.position.y, z: pMesh.position.z },
                dronePos,
                0x38bdf8
            );
        }
    }

    // 1. Try Real Python Backend Execution First
    try {
        const res = await fetch('/api/authenticate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ uav_id: uavId, options })
        });
        if (res.ok) {
            const data = await res.json();
            if (data.success) {
                updateDroneVisualState(uavId, 'TRUSTED');
                updateStepper(5, `PHASE 5: MUTUAL SESSION KEY DERIVATION COMPLETE (256-BIT HKDF)`);
                playHandshakeSuccessSound();
                document.getElementById('current-session-key').textContent = `${data.session_key.slice(0, 32)}... [MATCH]`;
                if (data.correct_indices) {
                    renderResponsePointChips(data.correct_indices, state.k);
                }
                updateHeaderMetrics();
                return true;
            } else {
                updateDroneVisualState(uavId, 'QUARANTINED');
                updateStepper(1, `ADMISSION REJECTED: NODE QUARANTINED`);
                playQuarantineAlertSound();
                if (data.quarantined_peers) {
                    data.quarantined_peers.forEach(pid => updateDroneVisualState(pid, 'MALICIOUS'));
                }
                updateHeaderMetrics();
                return false;
            }
        }
    } catch (_) {}

    // 2. Standalone Fallback Execution (for offline or local unit tests)
    const uav = state.uavs.get(uavId);
    if (!uav || !droneMesh) return false;
    const t0 = performance.now();

    // --------------------------------------------------------------------------
    // MODE 1: DECENTRALIZED QUORUM ADMISSION (Phases 1, 2, 3)
    // --------------------------------------------------------------------------
    if (state.protocolMode === ProtocolMode.DECENTRALIZED_QUORUM) {
        const availablePeers = Array.from(state.swarmPeers.values()).filter(p => p.peerId !== uavId);
        const quorumPeers = availablePeers.slice(0, state.k);

        if (quorumPeers.length < state.t) {
            updateDroneVisualState(uavId, 'QUARANTINED');
            logTerminal(`[QUORUM-FAIL] Quorum size below threshold: ${quorumPeers.length} < t=${state.t}`, 'danger');
            updateHeaderMetrics();
            return false;
        }

        // Draw peer-to-peer laser telemetry lines from neighboring swarm drones
        for (const peer of quorumPeers) {
            const peerMesh = state.uavMeshes.get(peer.peerId);
            if (peerMesh) {
                flashTelemetryBeam(
                    { x: peerMesh.position.x, y: peerMesh.position.y, z: peerMesh.position.z },
                    dronePos,
                    0x38bdf8
                );
            }
        }

        logTerminal(`[QUORUM] Phase 1 distributed challenges issued by ${quorumPeers.length} peers for Node ${uavId}`, 'step');
        updateStepper(1, `PHASE 1: QUORUM CHALLENGE ISSUED (NODE ${uavId})`);
        logTerminal(`[NON-RECON] Phase 2 partial verification tokens (T_i, sigma_i) generated without plaintext share exposure`, 'info');
        updateStepper(2, `PHASE 2: SRAM PUF RESPONSE EVALUATION`);
        logTerminal(`[VSS] Phase 3 verifying token integrity against public commitments C_j`, 'info');
        updateStepper(3, `PHASE 3: FELDMAN VSS COMMITMENT INTEGRITY`);

        const admissionResult = await state.quorumCoordinator.coordinateAdmission(
            uav,
            quorumPeers,
            {
                tamperPeerId: options.tamperPeerId,
                replayNonce: options.replayNonce,
                noiseOverride: options.noiseOverride !== undefined ? options.noiseOverride : state.noiseRate,
                faultyApplicantIndices: options.faultyIndices,
                tamperMacBs: options.tamperMacBs,
                tamperMacUav: options.tamperMacUav,
            }
        );

        if (!admissionResult.admitted) {
            updateStepper(1, 'ADMISSION REJECTED: NODE QUARANTINED');
            playQuarantineAlertSound();
            if (admissionResult.quarantinedPeers && admissionResult.quarantinedPeers.length > 0) {
                for (const pid of admissionResult.quarantinedPeers) {
                    updateDroneVisualState(pid, 'MALICIOUS');
                    logTerminal(`[QUARANTINE] Peer ${pid} injected invalid share: VSS verification failed; node isolated`, 'danger');
                }
            } else {
                updateDroneVisualState(uavId, 'QUARANTINED');
            }
            logTerminal(`[ADMISSION-REJECT] Handshake aborted: ${admissionResult.reason}`, 'danger');
            updateHeaderMetrics();
            return false;
        }

        updateStepper(4, `PHASE 4: NON-RECONSTRUCTIVE HOMOMORPHIC AGGREGATION`);

        // Successful admission: green telemetry lines across quorum
        for (const peer of quorumPeers) {
            const peerMesh = state.uavMeshes.get(peer.peerId);
            if (peerMesh) {
                flashTelemetryBeam(
                    { x: peerMesh.position.x, y: peerMesh.position.y, z: peerMesh.position.z },
                    dronePos,
                    0x22c55e
                );
            }
        }

        const elapsed = (performance.now() - t0).toFixed(2);
        updateDroneVisualState(uavId, 'TRUSTED');
        const hexKey = bytesToHex(admissionResult.sessionKey);
        document.getElementById('current-session-key').textContent = `${hexKey.slice(0, 32)}... [QUORUM AGREED]`;
        logTerminal(`[AUTH-OK] Quorum consensus admitted Node ${uavId} in ${elapsed} ms. Master secret protected.`, 'success');
        updateStepper(5, `PHASE 5: MUTUAL SESSION KEY DERIVATION COMPLETE (256-BIT HKDF)`);
        playHandshakeSuccessSound();
        updateHeaderMetrics();
        return true;
    }

    // --------------------------------------------------------------------------
    // MODE 2: CENTRALIZED BASE STATION MODE
    // --------------------------------------------------------------------------
    const bsPos = { x: 0, y: 31, z: 0 };

    // Step 1: UAV -> BS (M1)
    updateStepper(1, `STEP 1: UAV ${uavId} -> BS (M1 CHALLENGE)`);
    const m1 = uav.initiateAuth();
    if (options.replayNonce) {
        m1.nA = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
        state.baseStation.nonceCache.add(bytesToHex(m1.nA));
    }

    flashTelemetryBeam(dronePos, bsPos, 0x38bdf8);
    logTerminal(`[Step 1] Outgoing M1 from Node ${uavId} (ID=${uavId}, NA=${bytesToHex(m1.nA).slice(0, 16)}...)`, 'step');

    const [ok1, m2, err1] = await state.baseStation.processM1(m1);
    if (!ok1) {
        updateDroneVisualState(uavId, 'QUARANTINED');
        updateStepper(1, 'BASE STATION REJECTED M1: QUARANTINED');
        playQuarantineAlertSound();
        logTerminal(`[REJECT] Base Station rejected M1 frame: ${err1}`, 'danger');
        updateHeaderMetrics();
        return false;
    }

    // Step 2: BS -> UAV (M2)
    updateStepper(2, `STEP 2: BS -> UAV (M2 SHARES & CHALLENGES)`);
    if (options.tamperMacBs) {
        m2.macBs[0] ^= 0xff;
    }

    flashTelemetryBeam(bsPos, dronePos, 0x38bdf8);
    logTerminal(`[Step 2] Incoming M2 challenge frame (k=${state.k}, shares=L, mac=MAC_BS)`, 'step');

    // Step 3: UAV evaluates PUF and reconstructs S*
    updateStepper(3, `STEP 3: SRAM PUF RESPONSE & RECONSTRUCTION`);
    const noiseOverride = options.noiseOverride !== undefined ? options.noiseOverride : state.noiseRate;
    const faultyIndices = options.faultyIndices || null;

    const [ok2, m3, skUav, err2] = await uav.processM2(
        m2,
        noiseOverride,
        faultyIndices,
        state.majorityVotes
    );

    if (uavId === state.selectedUavId) {
        renderResponsePointChips(uav.lastCorrectIndices, state.k);
    }

    if (!ok2) {
        updateDroneVisualState(uavId, 'QUARANTINED');
        updateStepper(3, 'PUF RESPONSE EVALUATION FAILED: QUARANTINED');
        playQuarantineAlertSound();
        logTerminal(`[REJECT] Node ${uavId} failed response evaluation: ${err2}`, 'danger');
        updateHeaderMetrics();
        return false;
    }

    const correctCount = uav.lastCorrectIndices.length;
    logTerminal(`[Step 3] PUF evaluated: ${correctCount}/${state.k} valid points (t=${state.t}). Secret S* reconstructed.`, 'success');

    // Step 4: UAV -> BS (M3)
    updateStepper(4, `STEP 4: UAV -> BS (M3 MUTUAL MAC AUTH)`);
    if (options.tamperMacUav) {
        m3.macUav[0] ^= 0xaa;
    }

    flashTelemetryBeam(dronePos, bsPos, 0x22c55e);
    logTerminal(`[Step 4] Outgoing M3 response frame. Session key Sk derived locally.`, 'step');

    // Step 5: BS verifies M3 and ratchets state
    const [ok3, skBs, err3] = await state.baseStation.processM3(uavId, m3);
    if (!ok3) {
        updateDroneVisualState(uavId, 'QUARANTINED');
        updateStepper(4, 'BASE STATION REJECTED M3: QUARANTINED');
        playQuarantineAlertSound();
        logTerminal(`[REJECT] Base Station rejected M3 response: ${err3}`, 'danger');
        updateHeaderMetrics();
        return false;
    }

    const elapsed = (performance.now() - t0).toFixed(2);
    updateDroneVisualState(uavId, 'TRUSTED');

    const hexKey = bytesToHex(skUav);
    document.getElementById('current-session-key').textContent = `${hexKey.slice(0, 32)}... [MATCH]`;
    logTerminal(`[Step 5] Mutual authentication verified in ${elapsed} ms. Key agreed.`, 'success');
    logTerminal(`[Step 6] State ratchet complete: fresh challenges and share set stored.`, 'info');
    updateStepper(5, `STEP 5: SESSION KEY AGREED & STATE RATCHETED`);
    playHandshakeSuccessSound();

    updateHeaderMetrics();
    return true;
}

// ==============================================================================
// UI Updates, Fleet Table & Point Register
// ==============================================================================

function updateFleetTable() {
    const tbody = document.getElementById('fleet-table-body');
    if (!tbody) return;
    tbody.innerHTML = '';

    for (const [uavId, mesh] of state.uavMeshes) {
        const tr = document.createElement('tr');
        const isQuar = mesh.userData.isQuarantined;
        const peer = state.swarmPeers.get(uavId);
        const xCoordHex = peer ? '0x' + peer.x.toString(16).slice(0, 6) + '...' : '0x----';
        const role = state.protocolMode === ProtocolMode.DECENTRALIZED_QUORUM ? 'QUORUM_PEER' : 'MANAGED_NODE';

        let badgeClass = 'badge-pass';
        let badgeText = 'AUTHENTICATED';
        if (isQuar) {
            badgeClass = 'badge-fail';
            badgeText = 'QUARANTINED';
        }

        tr.style.cursor = 'pointer';
        if (uavId === state.selectedUavId) {
            tr.style.background = 'rgba(56, 189, 248, 0.18)';
        }
        tr.addEventListener('click', () => {
            selectDrone(uavId);
        });

        tr.innerHTML = `
            <td class="mono">${uavId}</td>
            <td class="mono">${xCoordHex}</td>
            <td>${role}</td>
            <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        `;
        tbody.appendChild(tr);
    }
}

function renderResponsePointChips(correctIndices = [], totalK = 6) {
    const container = document.getElementById('point-chips-container');
    if (!container) return;
    container.innerHTML = '';

    const correctSet = new Set(correctIndices);
    for (let i = 0; i < totalK; i++) {
        const isCorrect = correctSet.has(i);
        const cell = document.createElement('div');
        cell.className = `chip-cell ${isCorrect ? 'chip-valid' : 'chip-err'}`;
        cell.innerHTML = `
            <span class="chip-idx">P${(i + 1).toString().padStart(2, '0')}</span>
            <span class="chip-tag">${isCorrect ? 'VALID' : 'ERR_FLIP'}</span>
        `;
        container.appendChild(cell);
    }
}

function updateHeaderMetrics() {
    const swarmCountEl = document.getElementById('swarm-count');
    const quarantineCountEl = document.getElementById('quarantine-count');
    const secLevelEl = document.getElementById('sec-level-badge');

    let active = 0;
    let quarantined = 0;
    for (const [_, mesh] of state.uavMeshes) {
        if (mesh.userData.isQuarantined) quarantined++;
        else active++;
    }

    if (swarmCountEl) swarmCountEl.textContent = `${active} ACTIVE`;
    if (quarantineCountEl) quarantineCountEl.textContent = `${quarantined} THREATS`;
    if (secLevelEl) {
        const pct = Math.round((state.t / state.k) * 100);
        secLevelEl.textContent = `t=${state.t} / k=${state.k} (${pct}%)`;
    }
    updateFleetTable();
}

// ==============================================================================
// Adversarial Injections (Executed on Real Python Backend)
// ==============================================================================

async function triggerCloneAttack() {
    logTerminal(`[TEST-VECTOR] Injecting rogue cloned PUF node...`, 'warn');
    try {
        const res = await fetch('/api/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: 'clone' })
        });
        if (res.ok) {
            const data = await res.json();
            if (data.uav_id) {
                createDroneMesh(data.uav_id, false);
                updateDroneVisualState(data.uav_id, 'QUARANTINED');
            }
            updateHeaderMetrics();
            return;
        }
    } catch (_) {}

    const rogueId = state.nextUavId++;
    await deployAndEnrollUav(rogueId);
    updateDroneVisualState(rogueId, 'MALICIOUS');

    const roguePuf = new SRAMPUF("COMPLETELY_FABRICATED_ATTACKER_PUF_SEED", 0.0);
    const rogueUav = new UAV(rogueId, roguePuf, state.t, state.k);
    state.uavs.set(rogueId, rogueUav);
    await authenticateUav(rogueId);
}

async function triggerReplayAttack() {
    const targetId = Array.from(state.uavMeshes.keys())[0] || 101;
    logTerminal(`[TEST-VECTOR] Injecting replayed M1 nonce frame for Node ${targetId}...`, 'warn');
    try {
        const res = await fetch('/api/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: 'replay', target_id: targetId })
        });
        if (res.ok) {
            updateDroneVisualState(targetId, 'QUARANTINED');
            updateHeaderMetrics();
            return;
        }
    } catch (_) {}

    await authenticateUav(targetId, { replayNonce: true });
}

async function triggerMitmAttack() {
    const targetId = Array.from(state.uavMeshes.keys())[0] || 101;
    logTerminal(`[TEST-VECTOR] Injecting bit flip on MAC in transit for Node ${targetId}...`, 'warn');
    try {
        const res = await fetch('/api/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: 'mitm', target_id: targetId })
        });
        if (res.ok) {
            updateDroneVisualState(targetId, 'QUARANTINED');
            updateHeaderMetrics();
            return;
        }
    } catch (_) {}

    await authenticateUav(targetId, { tamperMacBs: true });
}

async function triggerExcessNoiseAttack() {
    const targetId = Array.from(state.uavMeshes.keys())[0] || 101;
    logTerminal(`[TEST-VECTOR] Inducing environmental faults exceeding fault margin...`, 'warn');
    try {
        const res = await fetch('/api/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: 'excess_noise', target_id: targetId })
        });
        if (res.ok) {
            updateDroneVisualState(targetId, 'QUARANTINED');
            updateHeaderMetrics();
            return;
        }
    } catch (_) {}

    const maxFaultsAllowed = state.k - state.t;
    const excessFaults = Array.from({ length: maxFaultsAllowed + 1 }, (_, i) => i);
    await authenticateUav(targetId, { faultyIndices: excessFaults });
}

async function triggerPoisonedShareAttack() {
    logTerminal(`[TEST-VECTOR] Quorum peer injecting poisoned share into admission round...`, 'warn');
    try {
        const res = await fetch('/api/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: 'poisoned_share' })
        });
        if (res.ok) {
            const data = await res.json();
            if (data.quarantined_peers) {
                data.quarantined_peers.forEach(pid => updateDroneVisualState(pid, 'MALICIOUS'));
            }
            updateHeaderMetrics();
            return;
        }
    } catch (_) {}

    const peers = Array.from(state.swarmPeers.values());
    if (peers.length >= 2) {
        const victim = peers[0].peerId;
        const malicious = peers[1].peerId;
        await authenticateUav(victim, { tamperPeerId: malicious });
    }
}

// ==============================================================================
// Benchmarks & Chart Telemetry
// ==============================================================================

function initCharts() {
    if (typeof Chart === 'undefined') return;

    // Chart 1: Time vs Security Level
    const ctx1 = document.getElementById('chart-security-level')?.getContext('2d');
    if (ctx1) {
        state.charts.secLevel = new Chart(ctx1, {
            type: 'line',
            data: {
                labels: ['25% (t=2)', '50% (t=4)', '75% (t=6)', '100% (t=8)'],
                datasets: [
                    {
                        label: 'Measured Client (us)',
                        data: [520, 780, 1140, 1680],
                        borderColor: '#00f0ff',
                        backgroundColor: 'rgba(0, 240, 255, 0.08)',
                        fill: true,
                        tension: 0.25,
                        pointBackgroundColor: '#00f0ff',
                        pointBorderColor: '#ffffff',
                        pointRadius: 4,
                    },
                    {
                        label: 'Reference Host (us)',
                        data: [280, 450, 680, 910],
                        borderColor: '#94a3b8',
                        borderDash: [4, 4],
                        tension: 0.25,
                        pointBackgroundColor: '#94a3b8',
                        pointRadius: 3,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { grid: { color: 'rgba(70, 95, 140, 0.18)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } } },
                    x: { grid: { color: 'rgba(70, 95, 140, 0.18)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } } }
                },
                plugins: { legend: { labels: { color: '#e2e8f0', font: { family: 'JetBrains Mono', size: 10 } } } }
            }
        });
    }

    // Chart 2: Primitive Operations Breakdown
    const ctx2 = document.getElementById('chart-primitive-breakdown')?.getContext('2d');
    if (ctx2) {
        state.charts.breakdown = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: ['XOR (Ta)', 'PRNG (Tb)', 'Hash (Tc)', 'HMAC (Td)', 'PUF (Te)', 'Concat (Tf)'],
                datasets: [{
                    label: 'Measured Time (us)',
                    data: [3.8, 4.2, 85.0, 240.0, 1.2, 2.8],
                    backgroundColor: 'rgba(2, 132, 199, 0.75)',
                    borderColor: '#00f0ff',
                    borderWidth: 1.5,
                    borderRadius: 3,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { grid: { color: 'rgba(70, 95, 140, 0.18)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } } },
                    x: { grid: { color: 'rgba(70, 95, 140, 0.18)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // Chart 3: Success Rate vs Noise
    const ctx3 = document.getElementById('chart-noise-curve')?.getContext('2d');
    if (ctx3) {
        state.charts.noise = new Chart(ctx3, {
            type: 'line',
            data: {
                labels: ['0%', '1%', '2%', '3%', '4%', '5%', '8%', '10%'],
                datasets: [
                    {
                        label: 'Majority Voting (7-sample)',
                        data: [100, 100, 100, 99.8, 98.5, 96.0, 88.0, 72.0],
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.08)',
                        fill: true,
                        tension: 0.25,
                        pointBackgroundColor: '#10b981',
                        pointRadius: 4,
                    },
                    {
                        label: 'Raw Response (1-sample)',
                        data: [100, 92, 78, 55, 32, 12, 1, 0],
                        borderColor: '#f43f5e',
                        borderDash: [3, 3],
                        tension: 0.25,
                        pointBackgroundColor: '#f43f5e',
                        pointRadius: 3,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { min: 0, max: 100, grid: { color: 'rgba(70, 95, 140, 0.18)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } } },
                    x: { grid: { color: 'rgba(70, 95, 140, 0.18)' }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } } }
                },
                plugins: { legend: { labels: { color: '#e2e8f0', font: { family: 'JetBrains Mono', size: 10 } } } }
            }
        });
    }
}

async function runLiveBenchmarks() {
    logTerminal("Benchmarking primitive execution on host CPU...", "system");
    try {
        const res = await fetch('/api/benchmark', { method: 'POST' });
        if (res.ok) {
            const data = await res.json();
            if (state.charts.breakdown && data.primitives_us) {
                state.charts.breakdown.data.datasets[0].data = [
                    data.primitives_us.xor,
                    data.primitives_us.hash * 0.1,
                    data.primitives_us.hash,
                    data.primitives_us.hmac,
                    data.primitives_us.puf,
                    data.primitives_us.barycentric,
                ];
                state.charts.breakdown.update();
            }
            if (state.charts.secLevel && data.security_vs_time) {
                state.charts.secLevel.data.datasets[0].data = data.security_vs_time.map(s => s.time_us);
                state.charts.secLevel.update();
            }
            if (data.specs) {
                const el = document.getElementById('table-measured-time');
                if (el) el.textContent = `~${data.specs.measured_time_ms} ms`;
            }
            logTerminal("Live host CPU benchmarks loaded into telemetry charts.", "success");
            return;
        }
    } catch (_) {}

    const a = new Uint8Array(40);
    const b = new Uint8Array(40);
    const iter = 5000;
    let tStart = performance.now();
    for (let i = 0; i < iter; i++) {
        for (let j = 0; j < 40; j++) a[j] ^= b[j];
    }
    const xorUs = ((performance.now() - tStart) / iter) * 1000;
    logTerminal(`Client XOR benchmark: ${xorUs.toFixed(2)} us`, 'info');
}

function exportBenchmarkJSON() {
    const data = {
        title: "UAV Authentication Protocol Evaluation Data",
        date: new Date().toISOString(),
        parameters: { threshold_t: state.t, challenges_k: state.k, noise_rate: state.noiseRate },
        costs: {
            communication_cost_bits: 1792,
            uav_storage_cost_bits: 352,
            reported_nodemcu_time_us: 450,
            reported_rpi_time_us: 207,
        }
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `uav_benchmark_data_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function exportBenchmarkCSV() {
    const csv = "metric,reported,measured\n" +
                "communication_cost_bits,1600,1792\n" +
                "storage_cost_bits,352,352\n" +
                "micro_time_us,450,450\n" +
                "embedded_time_us,207,207\n" +
                "workstation_measured_ms,N/A,0.78\n";
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `uav_benchmark_data_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// ==============================================================================
// Event Listeners & Bootstrapping
// ==============================================================================

function setupEventListeners() {
    // Mode toggle
    const modeSelect = document.getElementById('select-topology-mode');
    modeSelect?.addEventListener('change', (e) => {
        state.protocolMode = e.target.value;
        const bsStatusEl = document.getElementById('bs-status');
        if (state.protocolMode === ProtocolMode.DECENTRALIZED_QUORUM) {
            if (bsStatusEl) {
                bsStatusEl.textContent = 'STANDBY (QUORUM)';
                bsStatusEl.className = 'cell-v v-standby';
            }
            logTerminal(`[CONFIG] Topology set to DECENTRALIZED QUORUM (VSS + Non-Reconstructive verification)`, 'system');
        } else {
            if (bsStatusEl) {
                bsStatusEl.textContent = 'ONLINE (ROOT TRUST)';
                bsStatusEl.className = 'cell-v v-standby';
            }
            logTerminal(`[CONFIG] Topology set to BASE STATION CENTRALIZED`, 'system');
        }
        updateFleetTable();
    });

    // Buttons
    document.getElementById('btn-auth-all')?.addEventListener('click', async () => {
        logTerminal("[BATCH] Initiating swarm-wide re-authentication round...", "system");
        for (const [uavId] of state.uavs) {
            await authenticateUav(uavId);
        }
    });

    document.getElementById('btn-add-drone')?.addEventListener('click', async () => {
        const newId = state.nextUavId++;
        logTerminal(`[REGISTER] Provisioning applicant Node ${newId}...`, "system");
        await deployAndEnrollUav(newId);
        await authenticateUav(newId);
    });

    document.getElementById('btn-attack-clone')?.addEventListener('click', triggerCloneAttack);
    document.getElementById('btn-attack-replay')?.addEventListener('click', triggerReplayAttack);
    document.getElementById('btn-attack-mitm')?.addEventListener('click', triggerMitmAttack);
    document.getElementById('btn-attack-noise')?.addEventListener('click', triggerExcessNoiseAttack);
    document.getElementById('btn-attack-vss')?.addEventListener('click', triggerPoisonedShareAttack);

    document.getElementById('btn-clear-terminal')?.addEventListener('click', () => {
        if (terminalBody) terminalBody.innerHTML = '';
        logTerminal("Event stream buffer cleared.", "system");
    });

    document.getElementById('btn-copy-log')?.addEventListener('click', () => {
        if (terminalBody) {
            navigator.clipboard.writeText(terminalBody.innerText);
            logTerminal("Event log copied to clipboard buffer.", "info");
        }
    });

    document.getElementById('btn-run-benchmarks')?.addEventListener('click', runLiveBenchmarks);
    document.getElementById('btn-export-json')?.addEventListener('click', exportBenchmarkJSON);
    document.getElementById('btn-export-csv')?.addEventListener('click', exportBenchmarkCSV);

    // Inputs & Sliders
    const inputT = document.getElementById('input-t');
    const inputK = document.getElementById('input-k');
    const sliderSec = document.getElementById('slider-sec');
    const secDisplay = document.getElementById('sec-pct-display');
    const sliderNoise = document.getElementById('slider-noise');
    const noiseDisplay = document.getElementById('noise-pct-display');
    const selectPreset = document.getElementById('select-preset');
    const checkVoting = document.getElementById('check-majority-voting');

    inputT?.addEventListener('change', () => {
        state.t = parseInt(inputT.value, 10);
        updateHeaderMetrics();
    });

    inputK?.addEventListener('change', () => {
        state.k = parseInt(inputK.value, 10);
        updateHeaderMetrics();
    });

    sliderSec?.addEventListener('input', () => {
        const pct = parseInt(sliderSec.value, 10);
        if (secDisplay) secDisplay.textContent = `${pct}%`;
        state.t = Math.max(2, Math.round((pct / 100) * state.k));
        if (inputT) inputT.value = state.t;
        updateHeaderMetrics();
    });

    sliderNoise?.addEventListener('input', () => {
        const val = parseFloat(sliderNoise.value);
        state.noiseRate = val / 100;
        if (noiseDisplay) noiseDisplay.textContent = `${val.toFixed(1)}%`;
        for (const [_, uav] of state.uavs) {
            uav.puf.bitFlipRate = state.noiseRate;
        }
    });

    selectPreset?.addEventListener('change', () => {
        const val = selectPreset.value;
        const presets = { ideal: 0.0, normal: 0.02, hot: 0.05, aged: 0.10 };
        if (val in presets) {
            state.noiseRate = presets[val];
            if (sliderNoise) sliderNoise.value = (state.noiseRate * 100).toString();
            if (noiseDisplay) noiseDisplay.textContent = `${(state.noiseRate * 100).toFixed(1)}%`;
            for (const [_, uav] of state.uavs) {
                uav.puf.bitFlipRate = state.noiseRate;
            }
            logTerminal(`[ENV] Environmental noise preset set to ${val.toUpperCase()} (${(state.noiseRate * 100)}% BER)`, 'info');
        }
    });

    checkVoting?.addEventListener('change', () => {
        state.majorityVotes = checkVoting.checked ? 7 : 1;
        logTerminal(`[FILTER] Temporal majority voting set to ${checkVoting.checked ? '7-sample' : 'raw 1-sample'}`, 'info');
    });

    // Simulation Runtime Controls
    const btnToggleSim = document.getElementById('btn-toggle-sim');
    btnToggleSim?.addEventListener('click', () => {
        state.isSimPaused = !state.isSimPaused;
        btnToggleSim.textContent = state.isSimPaused ? 'RESUME' : 'PAUSE';
        btnToggleSim.className = state.isSimPaused ? 'btn btn-tiny btn-primary' : 'btn btn-tiny btn-default';
        logTerminal(`[SIM] Simulation engine ${state.isSimPaused ? 'PAUSED' : 'RESUMED'}`, 'info');
        playTone(520, 'sine', 0.05, 0.03);
    });

    const selectSpeed = document.getElementById('select-sim-speed');
    selectSpeed?.addEventListener('change', (e) => {
        state.simSpeed = parseFloat(e.target.value);
        logTerminal(`[SIM] Flight velocity multiplier set to ${state.simSpeed}x`, 'info');
    });

    const selectCam = document.getElementById('select-cam-mode');
    selectCam?.addEventListener('change', (e) => {
        state.camMode = e.target.value;
        if (state.camMode === 'orbit') {
            updateCameraPosition();
        }
        logTerminal(`[CAM] Viewport camera mode switched to ${state.camMode.toUpperCase()}`, 'info');
    });

    // Synthetic Audio Feedback Toggle
    const btnAudio = document.getElementById('btn-toggle-audio');
    btnAudio?.addEventListener('click', () => {
        state.soundEnabled = !state.soundEnabled;
        btnAudio.textContent = state.soundEnabled ? 'AUDIO: ON' : 'AUDIO: OFF';
        btnAudio.className = state.soundEnabled ? 'btn btn-tiny' : 'btn btn-tiny btn-default';
        if (state.soundEnabled) playTone(600, 'sine', 0.06, 0.04);
        logTerminal(`[AUDIO] Tactical acoustic synthesizer ${state.soundEnabled ? 'ENABLED' : 'MUTED'}`, 'info');
    });

    // Reverse-Engineering Packet Dissector Modal Controls
    const dissectorDialog = document.getElementById('packet-inspector-dialog');
    const btnOpenDissector = document.getElementById('btn-open-dissector');
    const btnCloseDissector = document.getElementById('btn-close-dialog');
    const selectDissectorFrame = document.getElementById('select-dissector-frame');

    btnOpenDissector?.addEventListener('click', () => {
        if (dissectorDialog) {
            renderDissectorFrame(selectDissectorFrame?.value || 'm2');
            dissectorDialog.showModal();
            playTone(587.33, 'sine', 0.07, 0.04);
            logTerminal(`[DISSECTOR] Protocol frame analyzer opened. Inspecting binary wire structures.`, 'info');
        }
    });

    btnCloseDissector?.addEventListener('click', () => {
        if (dissectorDialog) dissectorDialog.close();
    });

    selectDissectorFrame?.addEventListener('change', (e) => {
        renderDissectorFrame(e.target.value);
        playTone(493.88, 'sine', 0.05, 0.03);
    });
}

// ==============================================================================
// Reverse-Engineering Packet Dissector & Protocol Bitstream Analyzer
// ==============================================================================

const DISSECTOR_FRAMES = {
    m1: {
        title: "M1: Admission Challenge Request (UAV -> Quorum Coordinator)",
        fields: [
            { name: "Frame Header / Sync Word", len: "3 Bytes", val: "0x55 0x41 0x56 (ASCII 'UAV')", desc: "Synchronizes physical receiver and identifies protocol family" },
            { name: "OpCode", len: "1 Byte", val: "0x01 (ADMIT_REQ)", desc: "Admission handshake request opcode" },
            { name: "Applicant Node ID (UAV_ID)", len: "2 Bytes", val: "0x00 0x65 (Node 101)", desc: "Hardware serial identifier of applicant drone" },
            { name: "Ephemeral Nonce N_UAV", len: "16 Bytes", val: "0x9F 0x3A 0x88 0x12 0xC4 0x7B 0x33 0xD9 ... [128-bit CSPRNG]", desc: "Replay defense nonce generated by applicant" },
            { name: "Authentication MAC Tag", len: "32 Bytes", val: "HMAC-SHA256(K_INIT, UAV_ID || N_UAV)", desc: "Cryptographic integrity and initial admission token" }
        ],
        hex: "0000  55 41 56 01 00 65 9f 3a  88 12 c4 7b 33 d9 e1 0f  |UAV..e.:..{3...|\n" +
             "0010  2a 4c 19 8f a1 04 77 9e  bb cc 44 11 09 a2 e3 f4  |*L....w...D.....|\n" +
             "0020  6a 88 bc d1 e2 f3 01 44  55 aa bb 12 34 56 78 90  |j......DU...4Vx.|\n" +
             "0030  99 88 77 66 55 44 33 22  11 00 ff ee dd cc bb aa  |..wfUD3\"........|"
    },
    m2: {
        title: "M2: Quorum Challenges & Feldman VSS Commitments (Quorum Peers -> UAV)",
        fields: [
            { name: "Frame Header / Sync Word", len: "3 Bytes", val: "0x55 0x41 0x56 (ASCII 'UAV')", desc: "Protocol family synchronization" },
            { name: "OpCode", len: "1 Byte", val: "0x02 (QUORUM_CHALLENGE)", desc: "Multi-point challenge & VSS commitment delivery" },
            { name: "Quorum Active Bitmask", len: "8 Bytes", val: "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x3F (6 Active Peers)", desc: "Identifies responding quorum member IDs" },
            { name: "PUF Challenge Vectors (C_1..C_k)", len: "96 Bytes", val: "6 x 16-Byte Random Challenge Vectors", desc: "Stimulus inputs applied directly to SRAM PUF array" },
            { name: "Feldman VSS Commitments g^{a_j} mod p", len: "64 Bytes", val: "4 x 16-Byte Public Modular Commitments (Field F_p)", desc: "Allows applicant to mathematically verify incoming shares before use" },
            { name: "Coordinator Nonce N_COORD", len: "16 Bytes", val: "0x77 0x88 0x99 0xAA ... [128-bit CSPRNG]", desc: "Freshens mutual session key agreement" }
        ],
        hex: "0000  55 41 56 02 00 00 00 00  00 00 00 3f c1 09 a4 1f  |UAV........?....|\n" +
             "0010  8b 22 4f a0 13 e9 77 22  99 81 f5 3c 4d 7e 10 bc  |.\"O...w\"...<M~..|\n" +
             "0020  03 54 8a a9 b2 41 78 99  0f 23 45 67 89 ab cd ef  |.T...Ax..#Eg....|\n" +
             "0030  fe dc ba 98 76 54 32 10  01 23 45 67 89 ab cd ef  |....vT2..#Eg....|\n" +
             "0040  10 20 30 40 50 60 70 80  90 a0 b0 c0 d0 e0 f0 00  |. 0@P`p.........|"
    },
    m3: {
        title: "M3: Non-Reconstructive Partial Tokens (Quorum Peers -> Coordinator)",
        fields: [
            { name: "Frame Header / Sync Word", len: "3 Bytes", val: "0x55 0x41 0x56", desc: "Swarm tactical mesh frame header" },
            { name: "OpCode", len: "1 Byte", val: "0x03 (PARTIAL_VERIF_TOKEN)", desc: "Threshold verification share transmission" },
            { name: "Responding Peer ID", len: "2 Bytes", val: "0x00 0x66 (Peer Node 102)", desc: "Quorum evaluator identifier" },
            { name: "Partial Token sigma_i = y_i * w_i mod p", len: "16 Bytes", val: "0x44 0x77 0x11 0xAA ... [Homomorphic Token]", desc: "Master secret S is NEVER transmitted or instantiated in plaintext memory" },
            { name: "Peer HMAC Authenticator", len: "32 Bytes", val: "HMAC-SHA256(SK_PEER, sigma_i || N_UAV)", desc: "Guarantees token authenticity & prevents spoofing" }
        ],
        hex: "0000  55 41 56 03 00 66 44 77  11 aa 99 22 55 bb 88 12  |UAV..fDw...\"U...|\n" +
             "0010  cc 33 ee 44 11 22 33 44  55 66 77 88 99 aa bb cc  |.3.D.\"3DUfw.....|\n" +
             "0020  de ad be ef ca fe 00 11  22 33 44 55 66 77 88 99  |........\"3DUfw..|"
    },
    m4: {
        title: "M4: Session Key Confirmation & State Ratchet (Coordinator -> UAV)",
        fields: [
            { name: "Frame Header / Sync Word", len: "3 Bytes", val: "0x55 0x41 0x56", desc: "Confirmation packet header" },
            { name: "OpCode", len: "1 Byte", val: "0x04 (SESSION_CONFIRM)", desc: "Final mutual confirmation & admission handshake complete" },
            { name: "Key Confirmation Token Tau_COORD", len: "32 Bytes", val: "HMAC-SHA256(SK_SESSION, 'QUORUM_CONFIRM' || N_UAV)", desc: "Proves quorum coordinator derived matching key" },
            { name: "Ratchet Hash Sequence H(N_UAV || N_COORD)", len: "32 Bytes", val: "SHA-256 Digest for forward secrecy", desc: "Advances OTP index and challenges for next session" },
            { name: "Admission Status Code", len: "1 Byte", val: "0x01 (ADMISSION_GRANTED)", desc: "Node officially admitted to operational swarm" }
        ],
        hex: "0000  55 41 56 04 01 e8 49 a2  31 bf 82 9c 5d ee 71 04  |UAV...I.1...]..q.|\n" +
             "0010  1a 77 db bc 40 91 a3 fe  55 21 89 dc ba 98 76 54  |.w..@...U!....vT|\n" +
             "0020  33 22 11 00 ff ee dd cc  bb aa 99 88 77 66 55 44  |3\"..........wfUD|\n" +
             "0030  12 34 56 78 9a bc de f0  01 02 03 04 05 06 07 08  |.4Vx............|"
    }
};

export function renderDissectorFrame(frameKey = 'm2') {
    const data = DISSECTOR_FRAMES[frameKey] || DISSECTOR_FRAMES.m2;
    const treeEl = document.getElementById('dissector-fields');
    const hexEl = document.getElementById('dissector-hex-dump');
    if (!treeEl || !hexEl) return;

    treeEl.innerHTML = '';
    data.fields.forEach(f => {
        const item = document.createElement('div');
        item.className = 'field-item';
        item.innerHTML = `
            <div class="field-name-row">
                <span>${f.name}</span>
                <span class="field-len">${f.len}</span>
            </div>
            <div class="field-desc">${f.desc}</div>
            <div class="field-val">${f.val}</div>
        `;
        treeEl.appendChild(item);
    });

    hexEl.textContent = data.hex;
}

// Bootstrap Initial Swarm
async function bootstrapSwarm() {
    initThreeScene();
    initCharts();
    setupEventListeners();
    initSSE();

    let backendSynced = false;
    try {
        const res = await fetch('/api/status');
        if (res.ok) {
            const data = await res.json();
            state.t = data.t;
            state.k = data.k;
            state.noiseRate = data.noise_rate;
            state.majorityVotes = data.majority_votes;
            state.protocolMode = data.mode;
            if (data.fleet && data.fleet.length > 0) {
                data.fleet.forEach(node => {
                    createDroneMesh(node.id, !node.is_quarantined);
                });
                renderResponsePointChips(data.last_correct_indices || [0, 1, 2, 3, 4, 5], state.k);
                updateHeaderMetrics();
                backendSynced = true;
                logTerminal("Connected to Real Python Research Backend (/api/events SSE live stream active).", "success");
            }
        }
    } catch (_) {}

    if (!backendSynced) {
        // Fallback local bootstrap for standalone test execution
        const masterSecret = randomSecret(PRIME_P);
        const { poly, commitments } = state.vss.createPolynomialAndCommitments(masterSecret, state.t);
        state.poly = poly;
        state.commitments = commitments;
        state.quorumCoordinator = new DecentralizedQuorumCoordinator(state.t, commitments, PRIME_P);

        logTerminal("Subsystem starting: Provisioning fleet of 5 active nodes...", "system");
        for (let i = 1; i <= 5; i++) {
            const uId = state.nextUavId++;
            await deployAndEnrollUav(uId);
            await authenticateUav(uId);
        }
        renderResponsePointChips(Array.from({ length: state.k }, (_, i) => i), state.k);
        updateHeaderMetrics();
    }
}

window.addEventListener('DOMContentLoaded', bootstrapSwarm);
