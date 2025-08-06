# Stage 1: Builder
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal as builder

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create directory structure
RUN mkdir -p /app && \
    mkdir -p /opt/toxin

# Clone Toxssin
RUN git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin

# Install Python dependencies to a custom directory
ENV PIP_TARGET=/python-packages
RUN mkdir -p ${PIP_TARGET} && \
    pip install --no-cache-dir --target=${PIP_TARGET} -r /app/requirements.txt && \
    cd /opt/toxin && \
    pip install --no-cache-dir --target=${PIP_TARGET} -r requirements.txt && \
    playwright install chromium && \
    playwright install-deps

# Create non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app /opt/toxin ${PIP_TARGET}

# Stage 2: Final image
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Create directory structure
RUN mkdir -p /app && \
    mkdir -p /opt/toxin && \
    mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    mkdir -p /tmp/toxin-scans && \
    chmod 777 /tmp/toxin-scans

# Copy installed Python packages from custom directory
COPY --from=builder --chown=scanner:scanner /python-packages /usr/local/lib/python3.8/dist-packages
COPY --from=builder --chown=scanner:scanner /opt/toxin /opt/toxin
COPY --from=builder --chown=scanner:scanner /usr/bin/sqlmap /usr/bin/sqlmap

# Copy application code
COPY --chown=scanner:scanner . /app

# Create non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app /opt/toxin

USER scanner

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/usr/local/lib/python3.8/dist-packages \
    TMPDIR=/tmp/toxin-scans \
    PATH="/usr/local/lib/python3.8/dist-packages/bin:${PATH}"

HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python3", "main.py"]
