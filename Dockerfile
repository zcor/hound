# Hound SaaS Stack Dockerfile
# Base image with Python 3.11
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PORT=8000

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash hound \
    && chown -R hound:hound /app
USER hound

# Create .hound directory for local storage
RUN mkdir -p /home/hound/.hound

# Expose default port (Railway sets $PORT)
EXPOSE ${PORT}

# Default command for Railway (uses $PORT env var)
CMD uvicorn server.api:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'
