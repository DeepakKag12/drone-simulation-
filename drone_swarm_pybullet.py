"""
Drone Swarm Simulation with Shamir Secret Sharing Authentication
Web-streaming version: PyBullet DIRECT mode + MJPEG over HTTP
No VNC, no X11, no websockify — works on any cloud platform (Render, HF, etc.)
"""

import math, random, time, hashlib, secrets, threading, io, os, json, queue
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, List, Tuple, Optional
from urllib.parse import parse_qs, urlparse

import pybullet as p
import pybullet_data
import numpy as np
from PIL import Image

PORT = int(os.environ.get("PORT", 7860))

# ─────────────────────────────────────────────
# Shared state between simulation and HTTP threads
# ─────────────────────────────────────────────
_frame_lock   = threading.Lock()
_current_frame: bytes = b""          # latest JPEG frame

_status_lock  = threading.Lock()
_status: dict = {"count": 0, "leader": None,
                 "attack": "invalid_signature", "blacklist": 0}

_log_lock     = threading.Lock()
_log_lines:  List[str] = []          # rolling 120-line terminal log

_cmd_queue:   queue.Queue = queue.Queue()  # HTTP → sim commands

_cam_lock     = threading.Lock()
_cam = {"distance": 80.0, "yaw": 45.0, "pitch": -45.0,
        "tx": 0.0, "ty": 0.0, "tz": 10.0}


def push_log(msg: str):
    with _log_lock:
        _log_lines.append(msg)
        if len(_log_lines) > 120:
            del _log_lines[0]
    print(msg, flush=True)


# ─────────────────────────────────────────────
# Embedded Web UI
# ─────────────────────────────────────────────
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Drone Swarm Simulation</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{width:100%;height:100%;background:#0d1117;color:#e6edf3;font-family:monospace;overflow:hidden}
#wrap{display:flex;width:100%;height:100%}
#view{flex:1;position:relative;background:#000;display:flex;align-items:center;justify-content:center}
#stream{width:100%;height:100%;object-fit:contain}
#sidebar{width:280px;min-width:280px;background:#161b22;border-left:1px solid #30363d;display:flex;flex-direction:column;overflow:hidden}
.section{padding:12px;border-bottom:1px solid #30363d}
.section h3{font-size:11px;letter-spacing:1px;color:#8b949e;text-transform:uppercase;margin-bottom:10px}
.btn{width:100%;padding:9px 12px;margin-bottom:7px;border:none;border-radius:6px;cursor:pointer;font-family:monospace;font-size:13px;font-weight:600;transition:opacity .15s}
.btn:hover{opacity:.85}
.btn:active{opacity:.65}
.btn-green {background:#238636;color:#fff}
.btn-red   {background:#da3633;color:#fff}
.btn-orange{background:#e3b341;color:#000}
.btn-gray  {background:#30363d;color:#e6edf3}
#status-bar{padding:8px 12px;font-size:11px;color:#8b949e;border-bottom:1px solid #30363d}
.cam-row{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:11px}
.cam-row label{width:55px;color:#8b949e;flex-shrink:0}
.cam-row input{flex:1;accent-color:#58a6ff}
.cam-row span{width:32px;text-align:right;font-size:10px;color:#58a6ff}
#log{flex:1;overflow-y:auto;padding:8px;font-size:10px;line-height:1.6;color:#8b949e}
#log .ok  {color:#3fb950}
#log .warn{color:#e3b341}
#log .err {color:#f85149}
#log .info{color:#58a6ff}
#connecting{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
  color:#58a6ff;font-size:16px;text-align:center;pointer-events:none}
</style>
</head>
<body>
<div id="wrap">
  <div id="view">
    <img id="stream" src="/stream" alt="simulation">
    <div id="connecting">⏳ Loading simulation...</div>
  </div>
  <div id="sidebar">
    <div id="status-bar">Connecting...</div>
    <div class="section">
      <h3>Controls</h3>
      <button class="btn btn-green"  onclick="cmd('add_real')">➕ Add REAL Drone</button>
      <button class="btn btn-red"    onclick="cmd('add_fake')">💀 Add FAKE Drone</button>
      <button class="btn btn-orange" onclick="cmd('cycle_attack')">🔧 Cycle Attack Type</button>
      <button class="btn btn-gray"   onclick="cmd('remove')">➖ Remove Drone</button>
    </div>
    <div class="section">
      <h3>Camera</h3>
      <div class="cam-row">
        <label>Distance</label>
        <input type="range" id="c_dist"  min="20" max="150" value="80"   oninput="updateCam()">
        <span id="v_dist">80</span>
      </div>
      <div class="cam-row">
        <label>Yaw</label>
        <input type="range" id="c_yaw"   min="-180" max="180" value="45" oninput="updateCam()">
        <span id="v_yaw">45</span>
      </div>
      <div class="cam-row">
        <label>Pitch</label>
        <input type="range" id="c_pitch" min="-89" max="-10" value="-45" oninput="updateCam()">
        <span id="v_pitch">-45</span>
      </div>
    </div>
    <div class="section"><h3>Log</h3></div>
    <div id="log"></div>
  </div>
</div>
<script>
const streamEl = document.getElementById('stream');
const connEl   = document.getElementById('connecting');
streamEl.onload  = () => { connEl.style.display='none'; };
streamEl.onerror = () => { connEl.textContent='⚠️ Stream error — retrying...';
  setTimeout(()=>{ streamEl.src='/stream?t='+Date.now(); },2000); };

function cmd(action){
  fetch('/cmd/'+action).then(r=>r.json()).then(d=>{
    if(d.msg) flashLog(d.msg,'info');
  });
}

function updateCam(){
  const dist  = document.getElementById('c_dist').value;
  const yaw   = document.getElementById('c_yaw').value;
  const pitch = document.getElementById('c_pitch').value;
  document.getElementById('v_dist').textContent  = dist;
  document.getElementById('v_yaw').textContent   = yaw;
  document.getElementById('v_pitch').textContent = pitch;
  fetch(`/camera?distance=${dist}&yaw=${yaw}&pitch=${pitch}`);
}

function flashLog(msg, cls){
  const log = document.getElementById('log');
  const div = document.createElement('div');
  div.className = cls||'info';
  div.textContent = msg;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

// Poll status + log every second
let lastLogLen = 0;
setInterval(()=>{
  fetch('/status').then(r=>r.json()).then(d=>{
    document.getElementById('status-bar').textContent =
      `Drones: ${d.count} | Leader: D${d.leader} | Blacklist: ${d.blacklist} | Attack: ${d.attack}`;
  }).catch(()=>{});

  fetch('/logs?since='+lastLogLen).then(r=>r.json()).then(lines=>{
    const log = document.getElementById('log');
    lines.forEach(l=>{
      const div=document.createElement('div');
      div.className = l.startsWith('[AUTH]')||l.startsWith('[JOIN]')||l.includes('✅') ? 'ok'
                    : l.includes('❌')||l.includes('BLOCK')||l.includes('ERROR') ? 'err'
                    : l.includes('⚠️')||l.includes('ATTACK') ? 'warn' : 'info';
      div.textContent = l;
      log.appendChild(div);
    });
    if(lines.length>0){ log.scrollTop=log.scrollHeight; }
    lastLogLen += lines.length;
  }).catch(()=>{});
}, 1000);
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# HTTP Server
# ─────────────────────────────────────────────
class SimHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
        elif path == "/stream":
            self._stream_mjpeg()
        elif path == "/status":
            with _status_lock:
                data = json.dumps(_status).encode()
            self._send(200, "application/json", data)
        elif path == "/logs":
            since = int(params.get("since", ["0"])[0])
            with _log_lock:
                lines = _log_lines[since:]
            self._send(200, "application/json", json.dumps(lines).encode())
        elif path.startswith("/cmd/"):
            action = path[5:]
            if action in ("add_real", "add_fake", "cycle_attack", "remove"):
                _cmd_queue.put(action)
                self._send(200, "application/json", b'{"ok":true}')
            else:
                self._send(404, "text/plain", b"Unknown command")
        elif path == "/camera":
            with _cam_lock:
                if "distance" in params: _cam["distance"] = float(params["distance"][0])
                if "yaw"      in params: _cam["yaw"]      = float(params["yaw"][0])
                if "pitch"    in params: _cam["pitch"]    = float(params["pitch"][0])
            self._send(200, "application/json", b'{"ok":true}')
        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code, ct, body):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _stream_mjpeg(self):
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=--frame")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            while True:
                with _frame_lock:
                    frame = _current_frame
                if frame:
                    header = (
                        b"--frame\r\n"
                        b"Content-Type: image/jpeg\r\n"
                        + f"Content-Length: {len(frame)}\r\n\r\n".encode()
                    )
                    self.wfile.write(header + frame + b"\r\n")
                    self.wfile.flush()
                time.sleep(1 / 24)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def log_message(self, *_):
        pass  # silence access logs


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def start_http_server():
    srv = ThreadedHTTPServer(("0.0.0.0", PORT), SimHandler)
    push_log(f"[HTTP] Server started on port {PORT}")
    srv.serve_forever()


# ─────────────────────────────────────────────
# Camera frame capture
# ─────────────────────────────────────────────
def capture_frame(client_id: int, width=854, height=480) -> bytes:
    with _cam_lock:
        dist  = _cam["distance"]
        yaw   = math.radians(_cam["yaw"])
        pitch = math.radians(_cam["pitch"])
        tx, ty, tz = _cam["tx"], _cam["ty"], _cam["tz"]

    eye_x = tx + dist * math.cos(pitch) * math.sin(yaw)
    eye_y = ty - dist * math.cos(pitch) * math.cos(yaw)
    eye_z = tz - dist * math.sin(pitch)

    view = p.computeViewMatrix(
        cameraEyePosition=[eye_x, eye_y, eye_z],
        cameraTargetPosition=[tx, ty, tz],
        cameraUpVector=[0, 0, 1],
        physicsClientId=client_id,
    )
    proj = p.computeProjectionMatrixFOV(
        fov=60, aspect=width / height,
        nearVal=0.5, farVal=600,
        physicsClientId=client_id,
    )
    _, _, rgb, _, _ = p.getCameraImage(
        width=width, height=height,
        viewMatrix=view,
        projectionMatrix=proj,
        renderer=p.ER_TINY_RENDERER,
        physicsClientId=client_id,
    )
    arr = np.array(rgb, dtype=np.uint8).reshape(height, width, 4)
    img = Image.fromarray(arr[:, :, :3], "RGB")
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=70)
    return buf.getvalue()


# ─────────────────────────────────────────────
# Shamir Secret Sharing
# ─────────────────────────────────────────────
class ShamirSecretSharing:
    PRIME = 2**127 - 1

    def __init__(self):
        self.weights: List[int] = []
        self.x_coords: List[int] = []

    @staticmethod
    def _mod_inverse(a, prime):
        def ext(a, b):
            if a == 0: return b, 0, 1
            g, x1, y1 = ext(b % a, a)
            return g, y1 - (b // a) * x1, x1
        _, x, _ = ext(a % prime, prime)
        return (x % prime + prime) % prime

    def precompute_weights(self, x_coords, prime):
        k = len(x_coords)
        pre = [1] * (k + 1)
        for i in range(k): pre[i+1] = (pre[i] * (-x_coords[i])) % prime
        suf = [1] * (k + 1)
        for i in range(k-1, -1, -1): suf[i] = (suf[i+1] * (-x_coords[i])) % prime
        weights = []
        for i in range(k):
            num  = (pre[i] * suf[i+1]) % prime
            den  = 1
            for j in range(k):
                if i != j: den = (den * (x_coords[i] - x_coords[j])) % prime
            weights.append((num * self._mod_inverse(den, prime)) % prime)
        self.weights, self.x_coords = weights, x_coords
        return weights

    @staticmethod
    def generate_shares(secret, k, n):
        coeffs = [secret] + [secrets.randbelow(ShamirSecretSharing.PRIME) for _ in range(k-1)]
        return [(x, sum(c * pow(x, e, ShamirSecretSharing.PRIME)
                        for e, c in enumerate(coeffs)) % ShamirSecretSharing.PRIME)
                for x in range(1, n+1)]

    def reconstruct(self, shares, prime):
        s = 0
        for (xi, yi), wi in zip(shares, self.weights):
            s = (s + yi * wi) % prime
        return s


class DroneCredentials:
    def __init__(self, drone_id: int, is_legitimate: bool = True):
        self.drone_id = drone_id
        self.is_legitimate = is_legitimate
        self.private_key = secrets.token_hex(32) if is_legitimate else "FAKE_KEY_INVALID"
        self.public_key  = hashlib.sha256(self.private_key.encode()).hexdigest()
        self.certificate = {
            "drone_id": drone_id, "public_key": self.public_key,
            "issuer": "SwarmCA",
            "valid_from":  time.time() - 86400,
            "valid_until": time.time() + 86400 * 365,
            "is_legitimate": is_legitimate,
        }

    def sign(self, msg: str) -> str:
        return hashlib.sha256(f"{self.private_key}{msg}".encode()).hexdigest()

    def verify(self, msg: str, sig: str) -> bool:
        return secrets.compare_digest(
            sig, hashlib.sha256(f"{self.private_key}{msg}".encode()).hexdigest())


class AuthModule:
    PRIME = ShamirSecretSharing.PRIME

    def __init__(self, k: int = 3):
        self.k = k
        self.secret = secrets.randbelow(self.PRIME)
        self.shares:      Dict[int, Tuple[int, int]] = {}
        self.credentials: Dict[int, DroneCredentials] = {}
        self.blacklist:   set = set()
        self.challenges:  Dict[int, str] = {}
        self.sss = ShamirSecretSharing()

    def register(self, did: int, creds: DroneCredentials):
        self.credentials[did] = creds

    def distribute(self, ids: List[int]):
        n = len(ids)
        if n < self.k:
            push_log(f"[SHARES] Only {n} drones — need {self.k} to reconstruct"); return
        raw = ShamirSecretSharing.generate_shares(self.secret, self.k, n)
        self.shares = {did: raw[i] for i, did in enumerate(ids)}
        push_log(f"[SHARES] Distributed {n} shares (threshold={self.k})")

    def reconstruct(self, ids: List[int]) -> Optional[int]:
        pairs = [self.shares[d] for d in ids if d in self.shares]
        if len(pairs) < self.k: return None
        xs = [s[0] for s in pairs[:self.k]]
        if self.sss.x_coords != xs:
            self.sss.precompute_weights(xs, self.PRIME)
        return self.sss.reconstruct(pairs[:self.k], self.PRIME)

    def authenticate(self, new_id, creds, existing_ids, attack=None) -> Tuple[bool, str]:
        push_log(f"[AUTH] Drone {new_id} requesting join (attack={attack})")

        if new_id in self.blacklist:
            return False, "Blacklisted"

        cert = creds.certificate
        if attack == "tampered_cert":
            self.blacklist.add(new_id)
            push_log(f"[AUTH] ❌ Drone {new_id} BLOCKED: tampered certificate")
            return False, "Certificate tampered"
        if attack == "expired_cert":
            self.blacklist.add(new_id)
            push_log(f"[AUTH] ❌ Drone {new_id} BLOCKED: expired certificate")
            return False, "Certificate expired"
        if not cert.get("is_legitimate", True):
            self.blacklist.add(new_id)
            push_log(f"[AUTH] ❌ Drone {new_id} BLOCKED: illegitimate certificate")
            return False, "Invalid certificate"

        avail = [d for d in existing_ids if d in self.shares]
        if len(avail) < self.k:
            return False, f"Insufficient drones ({len(avail)}/{self.k})"

        sel = random.sample(avail, self.k)
        push_log(f"[AUTH] Selected drones for reconstruction: {sel}")

        rec = self.reconstruct(sel)
        if rec is None:
            return False, "Reconstruction failed"
        push_log(f"[AUTH] Secret reconstructed OK")

        nonce     = secrets.token_hex(16)
        challenge = hashlib.sha256(f"{rec}{new_id}{nonce}".encode()).hexdigest()
        self.challenges[new_id] = challenge
        push_log(f"[AUTH] Challenge sent: {challenge[:24]}...")

        if attack == "invalid_signature":
            self.blacklist.add(new_id)
            push_log(f"[AUTH] ❌ Drone {new_id} BLOCKED: invalid signature")
            del self.challenges[new_id]
            return False, "Invalid signature"

        sig = creds.sign(challenge)
        if not creds.verify(challenge, sig):
            self.blacklist.add(new_id)
            push_log(f"[AUTH] ❌ Drone {new_id} BLOCKED: signature mismatch")
            return False, "Signature mismatch"

        del self.challenges[new_id]
        push_log(f"[AUTH] ✅ Drone {new_id} authenticated successfully!")
        return True, "OK"


# ─────────────────────────────────────────────
# Drone
# ─────────────────────────────────────────────
def angle_wrap(a): return (a + math.pi) % (2 * math.pi) - math.pi


class Drone:
    def __init__(self, did, cid, r, theta, alt, cx, cy, bx, by, bz,
                 at_base=False, fake=False):
        self.id, self.cid = did, cid
        self.cx, self.cy  = cx, cy
        self.bx, self.by, self.bz = bx, by, bz
        self.alt  = alt
        self.fake = fake
        self.rejected      = False
        self.rejection_time = None

        if at_base:
            self.x, self.y, self.z = bx, by, alt
            dx, dy = bx - cx, by - cy
            self.r, self.theta = math.hypot(dx, dy), math.atan2(dy, dx)
            self.mode = "AT_BASE"
        else:
            self.r, self.theta = r, theta
            self.x = cx + r * math.cos(theta)
            self.y = cy + r * math.sin(theta)
            self.z = alt
            self.mode = "ORBIT"

        self.r_t, self.theta_t = self.r, self.theta
        self.battery = 100.0
        self.drain   = random.uniform(0.3, 0.7)
        self._mk_body()

    def _mk_body(self):
        col  = [1,0,0,1] if self.fake else [0.1,0.8,0.1,1]
        csid = p.createCollisionShape(p.GEOM_SPHERE, radius=0.5, physicsClientId=self.cid)
        vsid = p.createVisualShape(p.GEOM_SPHERE, radius=0.5, rgbaColor=col, physicsClientId=self.cid)
        self.bid = p.createMultiBody(
            baseMass=1, baseCollisionShapeIndex=csid, baseVisualShapeIndex=vsid,
            basePosition=[self.x, self.y, self.z],
            baseOrientation=[0,0,0,1], physicsClientId=self.cid)

    def set_color(self, rgba):
        p.changeVisualShape(self.bid, -1, rgbaColor=rgba, physicsClientId=self.cid)

    def _sync(self):
        p.resetBasePositionAndOrientation(
            self.bid, [self.x, self.y, self.z], [0,0,0,1], physicsClientId=self.cid)

    def mark_rejected(self):
        self.rejected = True; self.rejection_time = time.time()
        self.mode = "REJECTED"; self.set_color([1,0,0,1])

    def go_to_base(self):
        if self.mode in ("ORBIT","RECALIB"): self.mode = "TO_BASE"

    def go_from_base(self, r, theta):
        self.r_t, self.theta_t = r, theta; self.mode = "FROM_BASE"

    def destroy(self):
        try: p.removeBody(self.bid, physicsClientId=self.cid)
        except: pass

    def step(self, dt):
        self.battery = max(0, self.battery - self.drain * dt)
        m = self.mode

        if m == "REJECTED":
            self.z = max(0, self.z - 5*dt); self._sync(); return

        if m == "ORBIT":
            self.r += 0.8*(self.r_t - self.r)*dt
            self.theta = angle_wrap(self.theta + 0.3*dt)
            self.x = self.cx + self.r*math.cos(self.theta)
            self.y = self.cy + self.r*math.sin(self.theta)
            self.z = self.alt; self._sync()

        elif m == "RECALIB":
            er = self.r_t - self.r
            et = angle_wrap(self.theta_t - self.theta)
            self.r     += max(-4, min(4, 0.8*er))*dt
            self.theta  = angle_wrap(self.theta + max(-0.6,min(0.6, 1.2*et))*dt)
            self.x = self.cx + self.r*math.cos(self.theta)
            self.y = self.cy + self.r*math.sin(self.theta)
            self.z = self.alt; self._sync()

        elif m in ("TO_BASE","FROM_BASE"):
            if m == "TO_BASE":
                tx,ty,tz = self.bx, self.by, self.bz
            else:
                tx = self.cx + self.r_t*math.cos(self.theta_t)
                ty = self.cy + self.r_t*math.sin(self.theta_t)
                tz = self.alt
            dx,dy,dz = tx-self.x, ty-self.y, tz-self.z
            dist = math.sqrt(dx*dx+dy*dy+dz*dz)
            if dist < 0.3:
                self.x,self.y,self.z = tx,ty,tz
                self.mode = "AT_BASE" if m=="TO_BASE" else "ORBIT"
                if self.mode=="ORBIT": self.r,self.theta = self.r_t,self.theta_t
            else:
                s = min(8*dt, dist)
                self.x += dx/dist*s; self.y += dy/dist*s; self.z += dz/dist*s
                self.r = math.hypot(self.x-self.cx, self.y-self.cy)
                self.theta = math.atan2(self.y-self.cy, self.x-self.cx)
            self._sync()

        elif m == "AT_BASE":
            self.x,self.y,self.z = self.bx,self.by,self.bz; self._sync()


# ─────────────────────────────────────────────
# Swarm Leader / Manager
# ─────────────────────────────────────────────
class SwarmManager:
    ATTACK_TYPES = ["invalid_signature", "expired_cert", "tampered_cert"]

    def __init__(self, cid, drones, bldg_r, margin, d_safe, cx, cy, alt):
        self.cid, self.drones = cid, drones
        self.bldg_r, self.margin, self.d_safe = bldg_r, margin, d_safe
        self.cx, self.cy, self.alt = cx, cy, alt
        self.leader_id  = None
        self.r_now      = None
        self.attack_idx = 0
        self.fake_ctr   = 1000
        self.fakes: List[Drone] = []

        self.auth = AuthModule(k_threshold=3)
        for did in drones:
            self.auth.register(did, DroneCredentials(did, True))
        self.auth.distribute(list(drones))

    def _form(self):
        ids = sorted(self.drones)
        N   = len(ids)
        if not N: return
        r_base = self.bldg_r + self.margin
        r_safe = (self.d_safe / (2*math.sin(math.pi/N))) if N > 1 else r_base
        r = max(r_base, r_safe)
        self.r_now = r
        for i, did in enumerate(ids):
            th = 2*math.pi*i/N
            self.drones[did].r_t     = r
            self.drones[did].theta_t = angle_wrap(th)
            self.drones[did].mode    = "RECALIB"
        push_log(f"[Leader] Formation: N={N}, r={r:.1f}m")

    def _elect(self):
        if not self.drones: self.leader_id = None; return
        best = max(self.drones, key=lambda d: self.drones[d].battery)
        self.leader_id = best
        for did, d in self.drones.items():
            d.set_color([1,1,0,1] if did==best else [0.1,0.8,0.1,1])
        push_log(f"[Election] New leader: Drone {best}")

    def _update_status(self):
        with _status_lock:
            _status["count"]     = len(self.drones)
            _status["leader"]    = self.leader_id
            _status["attack"]    = self.ATTACK_TYPES[self.attack_idx]
            _status["blacklist"] = len(self.auth.blacklist)

    def add_real(self, base_pos):
        if len(self.drones) >= 8:
            push_log("[JOIN] ❌ Max capacity (8 drones)"); return
        new_id = max(self.drones)+1 if self.drones else 1
        creds  = DroneCredentials(new_id, True)
        ok, reason = self.auth.authenticate(new_id, creds, list(self.drones))
        if ok:
            r  = self.r_now or (self.bldg_r+self.margin)
            th = 2*math.pi*(len(self.drones))/(len(self.drones)+1)
            d  = Drone(new_id, self.cid, r, th, self.alt,
                       self.cx, self.cy, *base_pos, at_base=True, fake=False)
            d.set_color([0.2,1,0.4,1]); d.go_from_base(r, th)
            self.drones[new_id] = d
            self.auth.register(new_id, creds)
            self.auth.distribute(list(self.drones))
            self._form(); self._elect()
            push_log(f"[JOIN] ✅ Drone {new_id} joined the swarm!")
        else:
            push_log(f"[JOIN] ❌ Rejected: {reason}")
        self._update_status()

    def add_fake(self, base_pos):
        fid    = self.fake_ctr; self.fake_ctr += 1
        attack = self.ATTACK_TYPES[self.attack_idx]
        push_log(f"[ATTACK] Simulating: {attack.upper()} (fake drone {fid})")
        creds  = DroneCredentials(fid, False)
        r = (self.r_now or (self.bldg_r+self.margin)) + 15
        fd = Drone(fid, self.cid, r, random.uniform(0,2*math.pi),
                   self.alt+5, self.cx, self.cy, *base_pos, at_base=False, fake=True)
        _, reason = self.auth.authenticate(fid, creds, list(self.drones), attack)
        fd.mark_rejected()
        self.fakes.append(fd)
        push_log(f"[SECURITY] 🛡️ Fake drone {fid} BLOCKED — {reason}")
        self._update_status()

    def cycle_attack(self):
        self.attack_idx = (self.attack_idx+1) % len(self.ATTACK_TYPES)
        push_log(f"[ATTACK] Switched to: {self.ATTACK_TYPES[self.attack_idx].upper()}")
        self._update_status()

    def remove_one(self):
        if not self.drones: return
        followers = [d for d in self.drones if d != self.leader_id]
        did = max(followers) if followers else max(self.drones)
        push_log(f"[REMOVE] Drone {did} returning to base...")
        self.drones[did].go_to_base()

    def _remove_drone(self, did):
        was_leader = (did == self.leader_id)
        self.drones[did].destroy()
        del self.drones[did]
        self.auth.shares.pop(did, None)
        push_log(f"[REMOVE] Drone {did} removed (was_leader={was_leader})")
        if was_leader: self._elect()
        if self.drones:
            self._form()
            self.auth.distribute(list(self.drones))
        self._update_status()

    def process_commands(self, base_pos):
        while not _cmd_queue.empty():
            cmd = _cmd_queue.get()
            if cmd == "add_real":    self.add_real(base_pos)
            elif cmd == "add_fake":  self.add_fake(base_pos)
            elif cmd == "cycle_attack": self.cycle_attack()
            elif cmd == "remove":    self.remove_one()

    def step(self, dt):
        for d in self.drones.values(): d.step(dt)

        # RECALIB → ORBIT when close enough
        for d in self.drones.values():
            if d.mode=="RECALIB" and abs(d.r-d.r_t)<0.1 and abs(angle_wrap(d.theta-d.theta_t))<0.05:
                d.mode = "ORBIT"

        # Falling fakes cleanup
        for fd in self.fakes[:]:
            fd.step(dt)
            if fd.z <= 0 and time.time()-fd.rejection_time > 3:
                fd.destroy(); self.fakes.remove(fd)

        # Drones that reached base → remove them
        for did in [d for d,dr in self.drones.items() if dr.mode=="AT_BASE"]:
            self._remove_drone(did)


# ─────────────────────────────────────────────
# Environment helpers
# ─────────────────────────────────────────────
def make_box(cid, he, pos, color):
    cs = p.createCollisionShape(p.GEOM_BOX, halfExtents=he, physicsClientId=cid)
    vs = p.createVisualShape(p.GEOM_BOX, halfExtents=he, rgbaColor=color, physicsClientId=cid)
    p.createMultiBody(baseMass=0, baseCollisionShapeIndex=cs,
                      baseVisualShapeIndex=vs, basePosition=pos, physicsClientId=cid)

def build_city(cid, cx=0, cy=0):
    defs = [
        (-8,-5, 3,3,35, [.4,.4,.5,1]),
        ( 0,-6, 4,4,40, [.6,.6,.7,1]),
        ( 8,-4,2.5,2.5,30,[.45,.45,.55,1]),
        (-10,4, 2.5,2.5,18,[.7,.6,.5,1]),
        ( 6, 5, 2,2,12,  [.6,.7,.5,1]),
    ]
    for xo,yo,w,d,h,c in defs:
        make_box(cid, [w,d,h/2], [cx+xo, cy+yo, h/2], c)

def build_base(cid, pos=(50,0,0)):
    x,y,z = pos
    make_box(cid, [3,3,0.3], [x,y,z+0.3], [.1,.1,.9,1])

def draw_grid(cid):
    for i in range(-5,6):
        p.addUserDebugLine([i*10,-50,.01],[i*10,50,.01], [.25,.25,.25],1,0,physicsClientId=cid)
        p.addUserDebugLine([-50,i*10,.01],[50,i*10,.01], [.25,.25,.25],1,0,physicsClientId=cid)


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    push_log("="*60)
    push_log("  DRONE SWARM SIMULATION — Web Streaming Mode")
    push_log("="*60)

    # Start HTTP server in background thread
    t = threading.Thread(target=start_http_server, daemon=True)
    t.start()

    # Connect PyBullet in DIRECT mode (no display/X11 needed)
    cid = p.connect(p.DIRECT)
    push_log(f"[INIT] PyBullet connected in DIRECT mode (client_id={cid})")

    p.setAdditionalSearchPath(pybullet_data.getDataPath())
    p.setGravity(0, 0, -9.8, physicsClientId=cid)
    p.loadURDF("plane.urdf", physicsClientId=cid)

    cx, cy = 0.0, 0.0
    bldg_r, bldg_h = 15.0, 40.0
    base_pos = (50.0, 0.0, 0.0)
    alt      = bldg_h + 5.0

    build_city(cid, cx, cy)
    build_base(cid, base_pos)
    draw_grid(cid)

    # Initial drones
    drones: Dict[int, Drone] = {}
    N_init, r_init = 5, bldg_r + 25.0
    push_log(f"[INIT] Creating {N_init} drones at r={r_init:.1f}m, alt={alt:.1f}m")
    for i in range(N_init):
        th = 2*math.pi*i/N_init
        d  = Drone(i+1, cid, r_init, th, alt, cx, cy, *base_pos)
        drones[d.id] = d
        push_log(f"  Drone {d.id}: ({d.x:.1f}, {d.y:.1f}, {d.z:.1f})")

    mgr = SwarmManager(cid, drones, bldg_r, margin=15, d_safe=8,
                       cx=cx, cy=cy, alt=alt)
    mgr._form(); mgr._elect(); mgr._update_status()

    push_log(f"[INIT] ✅ Simulation ready — open http://localhost:{PORT}")
    push_log("[INIT] Controls available in web UI sidebar")

    dt = 1.0 / 30.0
    frame_every = 1   # capture every N steps
    step_count  = 0

    while True:
        mgr.process_commands(base_pos)
        mgr.step(dt)
        p.stepSimulation(physicsClientId=cid)

        step_count += 1
        if step_count % frame_every == 0:
            try:
                frame = capture_frame(cid)
                with _frame_lock:
                    global _current_frame
                    _current_frame = frame
            except Exception as e:
                push_log(f"[FRAME] Error: {e}")

        time.sleep(dt)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        push_log("[EXIT] Stopped by user")
    except Exception as e:
        import traceback
        push_log(f"[ERROR] {e}")
        traceback.print_exc()