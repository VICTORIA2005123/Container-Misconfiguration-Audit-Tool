# Secure Hardened Dockerfile
FROM python:3.12.3-slim-bookworm

# Establish security user with dedicated non-root UID/GID
RUN groupadd -r appgroup -g 10001 && \
    useradd -r -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

WORKDIR /app

# Safe COPY instruction with ownership preservation
COPY --chown=appuser:appgroup app.py /app/app.py

# Switch to unprivileged execution user
USER appuser

# Health check configuration
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080
CMD ["python3", "app.py"]
