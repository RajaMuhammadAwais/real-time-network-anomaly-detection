# syntax=docker/dockerfile:1
# Backend Dockerfile for Network Anomaly Detection
# Note: This installs TensorFlow and other ML deps which make the image large.

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TF_ENABLE_ONEDNN_OPTS=0 \
    TF_CPP_MIN_LOG_LEVEL=2

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap-dev \
        tshark \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -ms /bin/bash appuser

WORKDIR /app

# Copy and install Python deps first to maximize layer caching
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip && \
    pip install -r /app/requirements.txt

# Copy backend and frontend (templates/static)
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

# Expose service port
EXPOSE 5000

# Switch to non-root (note: packet capture features may require extra capabilities)
USER appuser

# Default command runs the enhanced app if present, fallback to app.py
CMD ["python", "-u", "backend/enhanced_app.py"]