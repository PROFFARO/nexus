# Nexus Honeypot System - Main Container
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    curl \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI for container management
RUN curl -fsSL https://get.docker.com -o get-docker.sh && \
    sh get-docker.sh && \
    rm get-docker.sh

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p logs data /var/log/honeypot /var/lib/honeypot

# Create non-root user for security
RUN useradd -m -u 1000 honeypot && \
    chown -R honeypot:honeypot /app /var/log/honeypot /var/lib/honeypot

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER honeypot

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python src/tools/health_check.py || exit 1

# Expose management port
EXPOSE 8080

# Default command
CMD ["python", "src/main.py", "--config", "config/honeypot.json"]