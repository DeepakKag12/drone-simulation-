#!/bin/bash
set -e

echo "===== Application Startup ====="
PORT_VALUE=${PORT:-7860}

mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix

# ── Stub HTTP server so Render health check passes immediately ──
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Starting...')
    def log_message(self, *a): pass
HTTPServer(('0.0.0.0', 7860), H).serve_forever()
" &
INIT_PID=$!
echo "Stub HTTP server started (pid=$INIT_PID)"

# ── Xvfb (virtual display) ──
echo "=== Starting Xvfb ==="
Xvfb :0 -screen 0 1280x720x24 -ac +extension GLX +render -noreset &
XVFB_PID=$!

echo "Waiting for Xvfb..."
for i in $(seq 1 60); do
    xdpyinfo -display :0 >/dev/null 2>&1 && echo "Xvfb ready." && break
    sleep 0.5
done

# ── Window manager ──
echo "=== Starting fluxbox ==="
DISPLAY=:0 fluxbox &
sleep 1

# ── x11vnc — plain RFB, no -bg flag ──
echo "=== Starting x11vnc ==="
x11vnc \
    -display :0 \
    -rfbport 5900 \
    -listen localhost \
    -nopw \
    -xkb \
    -forever \
    -shared \
    -nossl \
    -noipv6 \
    -rfbversion 3.8 \
    >> /tmp/x11vnc.log 2>&1 &
X11VNC_PID=$!

echo "Waiting for x11vnc on port 5900..."
for i in $(seq 1 40); do
    python3 -c "
import socket, sys
try:
    s = socket.create_connection(('127.0.0.1', 5900), timeout=1)
    s.close(); sys.exit(0)
except OSError:
    sys.exit(1)
" && echo "x11vnc ready (pid=$X11VNC_PID)." && break
    sleep 0.5
done

# ── Kill stub, launch websockify / NoVNC ──
echo "=== Starting websockify on port ${PORT_VALUE} ==="
kill $INIT_PID 2>/dev/null || true
sleep 1

websockify \
    --web=/usr/share/novnc/ \
    --heartbeat=30 \
    0.0.0.0:${PORT_VALUE} \
    localhost:5900 &
WSOCKIFY_PID=$!

echo "Waiting for websockify on port ${PORT_VALUE}..."
for i in $(seq 1 40); do
    python3 -c "
import socket, sys, os
port = int(os.environ.get('PORT', '7860'))
try:
    s = socket.create_connection(('127.0.0.1', port), timeout=1)
    s.close(); sys.exit(0)
except OSError:
    sys.exit(1)
" && echo "NoVNC ready at port ${PORT_VALUE}." && break
    sleep 0.5
done

echo "=== Starting PyBullet Simulation ==="
export DISPLAY=:0
export LIBGL_ALWAYS_SOFTWARE=1
export MESA_GL_VERSION_OVERRIDE=3.3
export PYTHONUNBUFFERED=1

while true; do
    python3 /app/drone_swarm_pybullet.py || {
        echo "Simulation exited ($?). Restarting in 5s..."
        sleep 5
    }
done &

echo "=== All services running. ==="
wait