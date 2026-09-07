# Intentionally Vulnerable Dockerfile for Security Auditing Demonstration
# WARNING: FOR LOCAL SECURITY TESTING ONLY - DO NOT USE IN PRODUCTION

FROM ubuntu:latest

# Hardcoded fake credentials
ENV DATABASE_PASSWORD="DEMO_NOT_A_REAL_SECRET_PASSWORD123"
ENV API_KEY="ghp_DEMO_FAKE_GITHUB_API_KEY_FOR_TESTING"

# Unsafe pipe-to-shell installation & SSH server installation
RUN apt-get update && \
    apt-get install -y openssh-server curl && \
    curl -fsSL https://example.com/unverified-script.sh | bash && \
    chmod 777 /etc

# ADD instead of COPY for local files
ADD app.py /app/app.py

# Explicit root user configuration
USER root

WORKDIR /app
CMD ["python3", "app.py"]
