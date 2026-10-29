# SecAgent — reproducible runtime with the real Kali toolchain.
#
# Build:
#   docker build -t secagent .
#
# Run (Linux — host networking so scans reach your lab network):
#   docker run --rm --network host --env-file .env secagent --target 192.168.1.10
#
# Run (safest — only reachable from inside the container's own network):
#   docker run --rm --env-file .env secagent --target 192.168.1.10

FROM python:3.11-slim

ARG FFUF_VERSION=2.1.0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# nmap and sqlmap are in the Debian repos. ffuf is not, so it is pulled from the
# release tarball; if that download fails the build still succeeds because the
# agent skips MCP servers whose binaries are missing.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL \
        "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm -f /tmp/ffuf.tar.gz \
    || echo "ffuf download failed - ffuf_server will be skipped at runtime"

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .

RUN useradd --create-home --uid 1000 secagent \
    && chown -R secagent:secagent /app
USER secagent

ENTRYPOINT ["python", "secagent.py"]
CMD ["--help"]
