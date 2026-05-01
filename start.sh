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

python3 - <<'EOF'
import socket
import time

def wait_for_port(host, port, timeout=15.0):
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            try:
                sock.connect((host, port))
                return True
            except OSError:
                time.sleep(0.5)
    return False

if not wait_for_port("127.0.0.1", 5900):
    raise SystemExit("x11vnc did not open port 5900 in time")
EOF

echo "=== Starting websockify (NoVNC) on port ${PORT_VALUE} ==="
kill $INIT_PID 2>/dev/null || true
sleep 1

websockify --web=/usr/share/novnc/ --wrap-mode=ignore 0.0.0.0:${PORT_VALUE} localhost:5900 &

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
