# Multi-stage build for security and efficiency
FROM python:3.11-slim as builder

# Security: Install only necessary packages and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Security: Add metadata labels
LABEL maintainer="security@company.com" \
      version="1.0.0" \
      description="Secure ECS Demo Application" \
      security.scan="required"

# Security: Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Security: Install only essential runtime packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Security: Set proper file permissions
RUN chmod -R 755 /app && \
    chmod 644 /app/app.py /app/requirements.txt

# Security: Switch to non-root user
USER appuser

# Security: Update PATH for user-installed packages
ENV PATH=/home/appuser/.local/bin:$PATH

# Security: Remove hardcoded secrets - use environment variables
# These should be set by the container orchestrator
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

EXPOSE 5000

# Security: Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Security: Use exec form to avoid shell injection
CMD ["python", "app.py"]