FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

WORKDIR /app

# Install only essential packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sqlmap \
        git \
        curl && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY requirements.txt ./

# Install Python dependencies, remove caches
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium --with-deps && \
    pip cache purge && \
    find /usr/local/lib/python*/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python*/site-packages -name "__pycache__" -type d -exec rm -rf {} + || true

# Setup shared memory and user
RUN mkdir -p /dev/shm && \
    chmod 1777 /dev/shm && \
    groupadd -r scanner && \
    useradd -r -g scanner scanner && \
    chown -R scanner:scanner /app
    # chown -R scanner:scanner /app /opt/toxin  # related to toxssin

USER scanner

# Copy application files
COPY --chown=scanner:scanner . /app

HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app
    # TMPDIR=/tmp/toxin-scans  # related to toxssin

CMD ["python3", "main.py"]

# ---- toxssin (commented out) ----
# RUN git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin || \
#     (rm -rf /opt/toxin && git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin) && \
#     rm -rf /opt/toxin/.git

# RUN cd /opt/toxin && \
#     pip install --no-cache-dir -r requirements.txt

# Make sure to uncomment if toxssin is needed in future
