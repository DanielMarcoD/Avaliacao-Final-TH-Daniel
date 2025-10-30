# Dockerfile
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates nmap && \
    rm -rf /var/lib/apt/lists/*

COPY src/requirements.txt /app/src/requirements.txt
RUN pip install --no-cache-dir -r /app/src/requirements.txt

COPY . /app

# usuário não-root
RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

ENV PYTHONUNBUFFERED=1
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:5000/login || exit 1

CMD ["python", "src/web_interface_a.py"]
