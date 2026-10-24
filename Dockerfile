# Multi-stage Docker build for ja4proxy
FROM python:3.11-slim

# Prevent Python from writing .pyc files & enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV JA4PROXY_HOST=0.0.0.0
ENV JA4PROXY_PORT=8888

WORKDIR /app

# Install system dependencies for certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy package metadata and source code
COPY pyproject.toml README.md /app/
COPY ja4proxy/ /app/ja4proxy/

# Install ja4proxy
RUN pip install --no-cache-dir .

# Expose default proxy port
EXPOSE 8888

# Default entrypoint starts the proxy listening on all interfaces
ENTRYPOINT ["ja4proxy", "start"]
