# Stage 1: Builder
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal as builder

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create directory structure
RUN mkdir -p /python-packages && \
    mkdir -p /opt/toxin

# Copy all files first (including requirements.txt)
COPY . .

# Install main requirements
ENV PIP_TARGET=/python-packages
RUN if [ -f requirements.txt ]; then \
        pip install --no-cache-dir --target=${PIP_TARGET} -r requirements.txt; \
    fi

# Install Toxin requirements if exists
RUN if [ -f /opt/toxin/requirements.txt ]; then \
        cd /opt/toxin && \
        pip install --no-cache-dir --target=${PIP_TARGET} -r requirements.txt; \
    fi

# Install Playwright
RUN playwright install chromium && \
    playwright install-deps

# Create non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /opt/toxin ${PIP_TARGET}

# Stage 2: Final image
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Create directory structure
RUN mkdir -p /opt/toxin && \
    mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    mkdir -p /tmp/toxin-scans && \
    chmod 777 /tmp/toxin-scans

# Copy installed Python packages
COPY --from=builder --chown=scanner:scanner /python-packages /usr/local/lib/python3.8/dist-packages
COPY --from=builder --chown=scanner:scanner /opt/toxin /opt/toxin
COPY --from=builder --chown=scanner:scanner /usr/bin/sqlmap /usr/bin/sqlmap

# Copy application code
COPY --chown=scanner:scanner . .

# Create non-root user
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner .

USER scanner

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/usr/local/lib/python3.8/dist-packages \
    TMPDIR=/tmp/toxin-scans \
    PATH="/usr/local/lib/python3.8/dist-packages/bin:${PATH}"

HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python3", "main.py"]
