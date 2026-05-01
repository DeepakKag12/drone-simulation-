# syntax=docker/dockerfile:1
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:0
ENV RESOLUTION=1280x720x24
ENV PYTHONUNBUFFERED=1

# Single apt layer with BuildKit cache mount — never re-downloads on rebuild
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    xvfb x11vnc websockify \
    novnc \
    fluxbox \
    libgl1-mesa-glx libgl1-mesa-dri libglib2.0-0 \
    x11-utils procps \
    && rm -rf /var/lib/apt/lists/*

# Symlink NoVNC index only if not already present
RUN [ -f /usr/share/novnc/index.html ] || \
    ln -s /usr/share/novnc/vnc.html /usr/share/novnc/index.html

WORKDIR /app

RUN useradd -m -u 1000 user \
    && mkdir -p /tmp/.X11-unix \
    && chmod 1777 /tmp/.X11-unix \
    && chown root:root /tmp/.X11-unix

# Copy requirements first — only reinstalls when requirements.txt changes
COPY requirements.txt .

# Single pip install with BuildKit cache
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r requirements.txt

COPY . .
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

RUN chown -R user:user /app
USER user

ENV PATH="/home/user/.local/bin:${PATH}"
EXPOSE 7860

CMD ["/app/start.sh"]
