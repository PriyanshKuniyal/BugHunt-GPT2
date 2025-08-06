# Multi-stage build for maximum size reduction
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal AS builder

WORKDIR /build

# Build stage: Install everything and clean
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin && \
    rm -rf /opt/toxin/.git

# Install to specific directory for copying
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --target /opt/python-libs "tensorflow-cpu>=2.8.0,<2.13.0" && \
    pip install --no-cache-dir --target /opt/python-libs -r requirements.txt && \
    cd /opt/toxin && \
    pip install --no-cache-dir --target /opt/python-libs -r requirements.txt && \
    playwright install chromium

# Final stage: Minimal runtime
FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

WORKDIR /app

# Install only runtime essentials and clean everything
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    curl \
    && \
    # NUCLEAR cleanup - remove everything unnecessary
    apt-get clean && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/* && \
    rm -rf /var/tmp/* && \
    rm -rf /var/cache/* && \
    rm -rf /usr/share/doc/* && \
    rm -rf /usr/share/man/* && \
    rm -rf /usr/share/locale/* && \
    rm -rf /var/log/* && \
    rm -rf /usr/share/info/* && \
    rm -rf /usr/share/lintian/* && \
    rm -rf /usr/share/common-licenses/* && \
    rm -rf /usr/share/pixmaps/* && \
    rm -rf /usr/share/applications/* && \
    rm -rf /usr/share/mime/* && \
    rm -rf /usr/share/glib-2.0/* && \
    rm -rf /usr/share/X11/* && \
    rm -rf /usr/lib/systemd/* && \
    find /usr/share -name "*.gz" -delete && \
    find /usr/share -name "*.bz2" -delete && \
    find /usr/share -name "*.xz" -delete && \
    find /usr/share -name "*.tar" -delete && \
    find /usr/share -name "*.deb" -delete && \
    # Remove ALL browsers except chromium
    find /home/pwuser/.cache/ms-playwright -name "*firefox*" -exec rm -rf {} + 2>/dev/null || true && \
    find /home/pwuser/.cache/ms-playwright -name "*webkit*" -exec rm -rf {} + 2>/dev/null || true && \
    find /home/pwuser/.cache/ms-playwright -name "*ffmpeg*" -exec rm -rf {} + 2>/dev/null || true && \
    # Remove pip entirely since we won't need it
    rm -rf /usr/local/lib/python*/dist-packages/pip* && \
    rm -rf /usr/local/bin/pip* && \
    # Clean Python standard library of unnecessary modules
    rm -rf /usr/lib/python*/test && \
    rm -rf /usr/lib/python*/tests && \
    rm -rf /usr/lib/python*/unittest && \
    rm -rf /usr/lib/python*/lib2to3 && \
    rm -rf /usr/lib/python*/ensurepip && \
    rm -rf /usr/lib/python*/idlelib && \
    rm -rf /usr/lib/python*/tkinter && \
    # Configure user and directories
    mkdir -p /dev/shm /tmp/toxin-scans && \
    chmod 1777 /dev/shm && \
    chmod 777 /tmp/toxin-scans && \
    groupadd -r scanner && \
    useradd -r -g scanner scanner

# Copy pre-built dependencies and toxin from builder
COPY --from=builder /opt/python-libs /usr/local/lib/python3.8/site-packages/
COPY --from=builder /opt/toxin /opt/toxin
COPY --from=builder /home/pwuser/.cache/ms-playwright /home/pwuser/.cache/ms-playwright

# Final Python package cleanup
RUN find /usr/local/lib/python*/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python*/site-packages -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "*.pyo" -delete && \
    find /usr/local/lib/python*/site-packages -name "tests" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "test" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "testing" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "examples" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "docs" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "*.md" -delete && \
    find /usr/local/lib/python*/site-packages -name "*.txt" -delete && \
    find /usr/local/lib/python*/site-packages -name "*.rst" -delete && \
    find /usr/local/lib/python*/site-packages -name "LICENSE*" -delete && \
    find /usr/local/lib/python*/site-packages -name "COPYING*" -delete && \
    find /usr/local/lib/python*/site-packages -name "CHANGELOG*" -delete && \
    # Clean TensorFlow specifically
    find /usr/local/lib/python*/site-packages/tensorflow -name "*test*" -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages/tensorflow -name "examples" -exec rm -rf {} + 2>/dev/null || true && \
    # Set ownership
    chown -R scanner:scanner /app /opt/toxin /home/pwuser

# Switch to non-root user
USER scanner

# Copy application files
COPY --chown=scanner:scanner . /app

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:8000/health || exit 1

# Runtime configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    TMPDIR=/tmp/toxin-scans \
    TF_CPP_MIN_LOG_LEVEL=2 \
    TF_ENABLE_ONEDNN_OPTS=0 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python3", "main.py"]
