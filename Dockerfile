# Use a smaller base image for even more space savings
FROM python:3.8-slim

WORKDIR /app

# Install system dependencies and Playwright in one optimized layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    ca-certificates \
    sqlmap \
    git \
    curl \
    && \
    # Add Microsoft's GPG key and repository for Playwright dependencies
    wget -q -O - https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    echo "deb [arch=amd64,arm64,armhf] https://packages.microsoft.com/repos/microsoft-ubuntu-focal-prod focal main" > /etc/apt/sources.list.d/microsoft.list && \
    apt-get update && \
    # Install Playwright system dependencies manually (lighter than full playwright image)
    apt-get install -y --no-install-recommends \
    libnss3 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libxss1 \
    libasound2 \
    && \
    # Install Python packages
    pip install --no-cache-dir --upgrade pip playwright && \
    # Install only chromium browser
    playwright install chromium && \
    # Clone toxin repository
    git clone --depth 1 https://github.com/t3l3machus/toxssin /opt/toxin && \
    rm -rf /opt/toxin/.git && \
    # Remove git after cloning
    apt-get remove -y git wget gnupg && \
    apt-get autoremove -y && \
    # Ultra-aggressive cleanup
    apt-get clean && \
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
    rm -rf /etc/apt/sources.list.d/* && \
    find /usr/share -name "*.gz" -delete && \
    find /usr/share -name "*.bz2" -delete && \
    find /usr/share -name "*.xz" -delete && \
    # Remove other playwright browsers to save massive space
    find /root/.cache/ms-playwright -name "*firefox*" -exec rm -rf {} + 2>/dev/null || true && \
    find /root/.cache/ms-playwright -name "*webkit*" -exec rm -rf {} + 2>/dev/null || true && \
    # Configure directories and user
    mkdir -p /dev/shm /tmp/toxin-scans && \
    chmod 1777 /dev/shm && \
    chmod 777 /tmp/toxin-scans && \
    groupadd -r scanner && \
    useradd -r -g scanner scanner

# Copy requirements and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    cd /opt/toxin && \
    pip install --no-cache-dir -r requirements.txt && \
    # Python cleanup
    pip cache purge && \
    find /usr/local/lib/python*/site-packages -name "*.pyc" -delete && \
    find /usr/local/lib/python*/site-packages -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "*.pyo" -delete && \
    find /usr/local/lib/python*/site-packages -name "tests" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python*/site-packages -name "test" -type d -exec rm -rf {} + 2>/dev/null || true && \
    # Set ownership
    chown -R scanner:scanner /app /opt/toxin

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
    TMPDIR=/tmp/toxin-scans

CMD ["python3", "main.py"]
