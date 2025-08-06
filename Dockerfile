# Stage 1: Base image with dependencies
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal as builder

# Install system dependencies & clean up in a single RUN layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone Toxssin (shallow clone)
RUN git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin

# Install Python dependencies (combine to minimize layers)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    cd /opt/toxin && \
    pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium && \
    playwright install-deps

# Configure shared memory and permissions
RUN mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    mkdir -p /tmp/toxin-scans && \
    chmod 777 /tmp/toxin-scans

# Create non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app /opt/toxin

# --- Stage 2: Final Slim Image ---
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Copy only necessary files from builder
COPY --from=builder /opt/toxin /opt/toxin
COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages
COPY --from=builder /usr/bin/sqlmap /usr/bin/sqlmap
COPY --from=builder /app /app

# Recreate directories & permissions
RUN mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    mkdir -p /tmp/toxin-scans && \
    chmod 777 /tmp/toxin-scans

# Recreate non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app /opt/toxin

USER scanner

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    TMPDIR=/tmp/toxin-scans

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command
CMD ["python3", "main.py"]
