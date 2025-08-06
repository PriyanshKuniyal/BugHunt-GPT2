FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Set working directory
WORKDIR /app

# Install system dependencies first (separate layers for better caching)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone Toxin with shallow clone and retry
RUN git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin || \
    (rm -rf /opt/toxin && git clone --depth 1 https://github.com/t3l3machus/toxin /opt/toxin)

# Install Python dependencies in optimal order
COPY requirements.txt ./
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

# Create non-root user and switch
RUN groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app /opt/toxin

USER scanner

# Copy application files (after dependencies for better layer caching)
COPY --chown=scanner:scanner . /app

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

# Runtime configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    TMPDIR=/tmp/toxin-scans

CMD ["python3", "main.py"]
