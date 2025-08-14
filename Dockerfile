# Multi-stage build for security and efficiency
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage with minimal base image
FROM python:3.11-slim

# Security: Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1000 appuser

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/appuser/.local

# Create application directory with proper ownership
WORKDIR /app
RUN chown -R appuser:appgroup /app

# Copy application code
COPY --chown=appuser:appgroup . .

# Security: Switch to non-root user
USER appuser

# Update PATH to include user-installed packages
ENV PATH=/home/appuser/.local/bin:$PATH

# Security: Run on non-privileged port
EXPOSE 8080

# Health check for container monitoring
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Use gunicorn for production-ready WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "30", "app:app"]