# Fomorian - Attack Scenario Generator for Wazuh SIEM Testing
# Docker image for easy deployment and testing

FROM python:3.11-slim

LABEL maintainer="PookaSec"
LABEL description="Attack scenario generator for Wazuh SIEM testing"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user for security
RUN groupadd -r fomorian && useradd -r -g fomorian fomorian

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install fomorian in editable mode
RUN pip install --no-cache-dir -e .

# Create directories for config and output
RUN mkdir -p /app/config /app/output /app/.fomorian \
    && chown -R fomorian:fomorian /app

# Switch to non-root user
USER fomorian

# Set default environment
ENV FOMORIAN_CONFIG_DIR=/app/config \
    FOMORIAN_OUTPUT_DIR=/app/output \
    FOMORIAN_STATE_DIR=/app/.fomorian

# Default command - show help
ENTRYPOINT ["fomorian"]
CMD ["--help"]
