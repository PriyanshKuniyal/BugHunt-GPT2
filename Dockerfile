# Fallback: Use original Playwright image but with aggressive optimization
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

WORKDIR /app

# Install system dependencies and optimize in single layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    curl \
    && \
    # Clone Toxin repository
    git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin && \
    rm -rf /opt/toxin/.git && \
    # Remove git immediately after cloning
    apt-get remove -y git && \
    apt-get autoremove -y && \
    # Configure directories and user
    mkdir -p /dev/shm /tmp/toxin-scans && \
    chmod 1777 /dev/shm && \
    chmod 777 /tmp/toxin-scans && \
    groupadd -r scanner && \
    useradd -r -g scanner scanner

# Copy requirements and install Python dependencies with TensorFlow fix
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    # Install TensorFlow first with compatible version
    pip install --no-cache-dir "tensorflow>=2.8.0,<2.13.0" && \
    # Install other requirements
    pip install --no-cache-dir -r requirements.txt && \
    cd /opt/toxin && \
    pip install --no-cache-dir -r requirements.txt && \
    # Install only chromium browser
    playwright install chromium && \
    # Aggressive cleanup
    pip cache purge && \
    find /usr/local/lib/python*/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python*/site-packages -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "*.pyo" -delete && \
    find /usr/local/lib/python*/site-packages -name "tests" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "test" -type d -exec rm -rf {} + 2>/dev/null || true && \
    # Remove other playwright browsers to save massive space
    find /home/pwuser/.cache/ms-playwright -name "*firefox*" -exec rm -rf {} + 2>/dev/null || true && \
    find /home/pwuser/.cache/ms-playwright -name "*webkit*" -exec rm -rf {} + 2>/dev/null || true && \
    # System cleanup
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/* && \
    rm -rf /var/tmp/* && \
    rm -rf /var/cache/* && \
    rm -rf /usr/share/doc/* && \
    rm -rf /usr/share/man/* && \
    rm -rf /usr/share/locale/* && \
    rm -rf /var/log/* && \
    find /usr/share -name "*.gz" -delete && \
    find /usr/share -name "*.bz2" -delete && \
    # Set ownership
    chown -R scanner:scanner /app /opt/toxin

# Switch to non-root user
USER scanner

# Copy application files
COPY --chown=scanner:scanner . /app

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

# Runtime configuration with TensorFlow optimizations
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    TMPDIR=/tmp/toxin-scans \
    TF_CPP_MIN_LOG_LEVEL=2 \
    TF_ENABLE_ONEDNN_OPTS=0 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python3", "main.py"]
