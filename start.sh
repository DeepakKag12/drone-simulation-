#!/bin/bash
set -e

echo "===== Application Startup ====="

export START_HEALTH_SERVER=${START_HEALTH_SERVER:-0}
PORT_VALUE=${PORT:-7860}

# Start a temporary HTTP server so the port is responsive while X starts
python3 - <<'EOF' &
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Starting...")

    def log_message(self, *args):
        pass

HTTPServer(("0.0.0.0", 7860), H).serve_forever()
EOF

INIT_PID=$!

echo "=== Starting Xvfb ==="
Xvfb :0 -screen 0 ${RESOLUTION:-1280x720x24} &

echo "Waiting for Xvfb to be ready..."
for i in $(seq 1 30); do
    if xdpyinfo -display :0 >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

echo "=== Starting window manager (fluxbox) ==="
fluxbox &

echo "=== Starting x11vnc ==="
x11vnc -display :0 -nopw -listen localhost -xkb -forever -shared &
sleep 2

echo "=== Starting websockify (NoVNC) on port ${PORT_VALUE} ==="
kill $INIT_PID 2>/dev/null || true
sleep 1

websockify --web=/usr/share/novnc/ ${PORT_VALUE} localhost:5900 &

for i in $(seq 1 30); do
    if curl -s http://localhost:${PORT_VALUE}/ >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "=== Starting PyBullet Simulation ==="
while true; do
    python3 /app/drone_swarm_pybullet.py || {
        echo "Simulation exited with code $?. Restarting in 5 seconds..."
        sleep 5
    }
done
