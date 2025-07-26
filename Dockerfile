FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Set working dir and install Python deps
WORKDIR /app
# First copy ONLY requirements.txt
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    playwright install chromium && \
    playwright install-deps

# Copy rest of the project
COPY . /app

CMD ["python3", "main.py"]
