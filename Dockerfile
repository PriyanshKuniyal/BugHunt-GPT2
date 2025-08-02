FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Set working dir and install Python deps
WORKDIR /app
# First copy ONLY requirements.txt
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium && \
    playwright install-deps


# Install sqlmap and dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    sqlmap \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/t3l3machus/toxin /opt/toxin \
    && cd /opt/toxin \
    && pip install -r requirements.txt

# Create shared memory directory
RUN mkdir -p /dev/shm && chmod 1777 /dev/shm
# Copy rest of the project
COPY . /app

CMD ["python3", "main.py"]
