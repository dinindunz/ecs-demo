# Multi-stage build for security and smaller attack surface
# Addresses JIRA ticket CO-29: Container Security Violations

# Build stage
FROM python:3.11.6-slim-bullseye AS builder

# Set build arguments for security
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Add metadata labels for security tracking
LABEL maintainer="security@company.com" \
      org.opencontainers.image.title="ECS Demo Secure" \
      org.opencontainers.image.description="Secure Flask application for ECS demo" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Company Security Team" \
      security.compliance.framework="Enterprise Security & Compliance Framework"

# Install security updates and build dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create virtual environment for dependency isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11.6-slim-bullseye AS production

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install only runtime security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        dumb-init \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create non-root user for security (addresses CO-29)
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin -c "App User" appuser

# Set working directory
WORKDIR /app

# Copy application files with proper ownership
COPY --chown=appuser:appuser app.py .

# Set secure file permissions
RUN chmod 755 /app && \
    chmod 644 /app/app.py

# Switch to non-root user (security requirement)
USER appuser

# Set security environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=production \
    FLASK_DEBUG=False \
    PORT=5000

# Expose port (non-privileged port)
EXPOSE 5000

# Add health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5)" || exit 1

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Run application as non-root user
CMD ["python", "app.py"]

# Security scanning metadata
LABEL security.scan.required="true" \
      security.vulnerability.scan="enabled" \
      security.compliance.pci-dss="required" \
      security.user.nonroot="true" \
      security.healthcheck="enabled"