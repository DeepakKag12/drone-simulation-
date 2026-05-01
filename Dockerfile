# syntax=docker/dockerfile:1

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:0
ENV RESOLUTION=1280x720x24
ENV PYTHONUNBUFFERED=1

# ── Install dependencies ──
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        xvfb x11vnc websockify novnc fluxbox \
        libgl1-mesa-glx libgl1-mesa-dri libgles2-mesa \
        mesa-utils mesa-vulkan-drivers \
        libglib2.0-0 x11-utils procps curl \
    && rm -rf /var/lib/apt/lists/*

# ── Fix NoVNC index ──
COPY novnc_index.html /usr/share/novnc/index.html

WORKDIR /app

# ── Create non-root user ──
RUN useradd -m -u 1000 user \
    && mkdir -p /tmp/.X11-unix \
    && chmod 1777 /tmp/.X11-unix

# ── Install Python deps ──
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r requirements.txt

# ── Copy app files ──
COPY . .

# ── Fix Windows line endings (DO NOT REMOVE) ──
RUN sed -i 's/\r$//' /app/start.sh

# ── Make executable ──
RUN chmod +x /app/start.sh

# ── Fix permissions ──
RUN chown -R user:user /app

USER user

ENV PATH="/home/user/.local/bin:${PATH}"

EXPOSE 7860

CMD ["./start.sh"]