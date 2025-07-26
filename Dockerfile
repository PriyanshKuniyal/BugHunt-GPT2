FROM mcr.microsoft.com/playwright/python:v1.48.0-focal

# Set working dir and install Python deps
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt && \
    playwright install chromium && \
    playwright install-deps

# Copy rest of the project
COPY . /app

RUN pip install -e .

CMD ["python3", "main.py"]
