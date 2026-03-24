# Hound SaaS Stack Dockerfile
FROM python:3.11-slim AS builder

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies into a copyable prefix for the runtime image.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy application code after dependencies for better caching.
COPY . .


FROM python:3.11-slim AS runner

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /app /app

RUN useradd --create-home --shell /bin/bash hound \
    && mkdir -p /home/hound/.hound \
    && chown -R hound:hound /app /home/hound

USER hound

EXPOSE ${PORT}

CMD uvicorn server.api:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'
