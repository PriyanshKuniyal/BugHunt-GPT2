FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Set working directory
WORKDIR /app

# Install system dependencies and clean up in single layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    curl \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/* && \
    rm -rf /var/tmp/*

# # Clone Toxin with shallow clone, install dependencies, and clean up git history
# RUN git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin || \
#     (rm -rf /opt/toxin && git clone --depth 1 https://github.com/t3l3machus/toxin /opt/toxin) && \
#     rm -rf /opt/toxin/.git

# Copy requirements early for better caching
COPY requirements.txt ./

# Install all Python dependencies in single optimized layer
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # cd /opt/toxin && \
    # pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium --with-deps && \
    pip cache purge && \
    find /usr/local/lib/python*/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python*/site-packages -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Configure directories and permissions in single layer
RUN mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    # chmod 777 /tmp/toxin-scans && \
    groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app
    # chown -R scanner:scanner /app /opt/toxin

# Switch to non-root user
USER scanner

# Copy application files (after dependencies for better layer caching)
COPY --chown=scanner:scanner . /app

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

# Runtime configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app
    # TMPDIR=/tmp/toxin-scans

CMD ["python3", "main.py"]
