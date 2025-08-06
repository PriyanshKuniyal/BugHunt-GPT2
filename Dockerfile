# Stage 1: Base image with dependencies
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal as builder

# Install system dependencies & clean up
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories with correct permissions upfront
RUN mkdir -p /app && \
    mkdir -p /opt/toxin && \
    chmod 777 /app /opt/toxin

# Clone Toxssin (shallow clone)
RUN git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt && \
    cd /opt/toxin && \
    pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium && \
    playwright install-deps

# Configure shared memory
RUN mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    mkdir -p /tmp/toxin-scans && \
    chmod 777 /tmp/toxin-scans

# Create non-root user and set ownership (now /app exists)
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app /opt/toxin

# --- Stage 2: Final Slim Image ---
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Create directories first with correct permissions
RUN mkdir -p /app && \
    mkdir -p /opt/toxin && \
    chmod 777 /app /opt/toxin && \
    mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    mkdir -p /tmp/toxin-scans && \
    chmod 777 /tmp/toxin-scans

# Copy files with correct ownership
COPY --from=builder --chown=scanner:scanner /opt/toxin /opt/toxin
COPY --from=builder --chown=scanner:scanner /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=builder --chown=scanner:scanner /usr/bin/sqlmap /usr/bin/sqlmap
COPY --chown=scanner:scanner . /app

# Create non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner

USER scanner

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    TMPDIR=/tmp/toxin-scans

HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python3", "main.py"]
