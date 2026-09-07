# Multi-stage container build for Container Misconfiguration Audit Tool
FROM python:3.12-slim-bookworm AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (curl for Trivy installation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Establish non-root execution user
RUN groupadd -r -g 10001 auditor && \
    useradd -r -u 10001 -g auditor -d /app -s /sbin/nologin auditor

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and project configuration
COPY . .
RUN pip install --no-cache-dir -e .

# Prepare reports directory and assign ownership
RUN mkdir -p /app/reports && \
    chown -R auditor:auditor /app

USER auditor

ENTRYPOINT ["container-audit"]
CMD ["--help"]
