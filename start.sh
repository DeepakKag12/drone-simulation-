#!/bin/bash
set -e

echo "=== Starting Xvfb ==="
Xvfb :0 -screen 0 ${RESOLUTION:-1280x720x24} &
XVFB_PID=$!

# Wait until Xvfb is actually ready, not just a fixed sleep
echo "Waiting for Xvfb to be ready..."
for i in $(seq 1 20); do
    if xdpyinfo -display :0 >/dev/null 2>&1; then
        echo "Xvfb is ready."
        break
    fi
    sleep 0.5
done

echo "=== Starting window manager (fluxbox) ==="
fluxbox &

echo "=== Starting x11vnc ==="
x11vnc -display :0 -nopw -listen localhost -xkb -forever -shared &
X11VNC_PID=$!

# Give x11vnc a moment to bind to port 5900
sleep 1

PORT_VALUE=${PORT:-7860}
echo "=== Starting websockify (NoVNC bridge on port ${PORT_VALUE}) ==="
websockify --web=/usr/share/novnc/ ${PORT_VALUE} localhost:5900 &
WEBSOCKIFY_PID=$!

sleep 1

echo "=== Starting PyBullet Simulation ==="
# Run in a loop so the container doesn't die if the simulation crashes
while true; do
    python3 /app/drone_swarm_pybullet.py || {
        echo "Simulation exited with code $?. Restarting in 5 seconds..."
        sleep 5
    }
done
