# syntax=docker/dockerfile:1

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:0
ENV PYTHONUNBUFFERED=1
ENV LIBGL_ALWAYS_SOFTWARE=1
ENV MESA_GL_VERSION_OVERRIDE=3.3

# ── System packages ──
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        xvfb \
        x11vnc \
        websockify \
        novnc \
        fluxbox \
        x11-utils \
        libgl1-mesa-glx \
        libgl1-mesa-dri \
        libgles2-mesa \
        mesa-utils \
        libglib2.0-0 \
        procps \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── NoVNC: replace default index with our auto-connect page ──
COPY novnc_index.html /usr/share/novnc/index.html

WORKDIR /app

# ── Python dependencies ──
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ── Application code ──
COPY drone_swarm_pybullet.py .
COPY start.sh .

# ── Fix Windows line endings & permissions ──
RUN sed -i 's/\r$//' /app/start.sh \
    && chmod +x /app/start.sh

EXPOSE 7860

CMD ["/app/start.sh"]