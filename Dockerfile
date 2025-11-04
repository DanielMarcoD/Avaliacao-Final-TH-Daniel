# Dockerfile
FROM python:3.12-slim
WORKDIR /app

# Install system dependencies including security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    nmap \
    wget \
    unzip \
    default-jre \
    git \
    perl \
    libnet-ssleay-perl \
    openssl \
    libauthen-pam-perl \
    libio-pty-perl \
    libmd-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto from GitHub (latest stable version)
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# Install OWASP ZAP (using cross-platform version that works reliably)
RUN cd /tmp \
    && wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2_15_0_unix.sh -O zap_installer.sh \
    && chmod +x zap_installer.sh \
    && ./zap_installer.sh -q -dir /opt/zaproxy \
    && rm zap_installer.sh \
    && rm -f /usr/local/bin/zap.sh \
    && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap.sh

COPY src/requirements.txt /app/src/requirements.txt
RUN pip install --no-cache-dir -r /app/src/requirements.txt

COPY . /app

# Create user first
RUN useradd -m scanner

# Make scripts executable
RUN chmod +x /app/src/start_zap.sh /app/entrypoint.sh

# Create ZAP home directory and give permissions
RUN mkdir -p /home/scanner/.ZAP \
    && chown -R scanner:scanner /home/scanner/.ZAP /app \
    && if [ -d "/opt/zaproxy" ]; then chown -R scanner:scanner /opt/zaproxy; fi \
    && if [ -d "/opt/ZAP_2.15.0" ]; then chown -R scanner:scanner /opt/ZAP_2.15.0; fi \
    && if [ -d "/opt/ZAP_2.14.0" ]; then chown -R scanner:scanner /opt/ZAP_2.14.0; fi \
    && chown -R scanner:scanner /opt/nikto

USER scanner

ENV PYTHONUNBUFFERED=1
ENV ZAP_PORT=8080
EXPOSE 5000 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:5000/login || exit 1

CMD ["/app/entrypoint.sh"]
