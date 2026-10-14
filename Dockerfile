FROM python:3.15-slim

# Set to the tag by GitHub Actions on release (e.g. v0.1.0)
ARG VERSION=dev

LABEL org.opencontainers.image.title="mailreports" \
      org.opencontainers.image.description="DMARC and SMTP TLS report viewer with plain-language explanations" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    APP_VERSION=${VERSION}

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin mailreports \
 && mkdir -p /data && chown mailreports /data
COPY mailreports ./mailreports

USER mailreports
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
CMD ["uvicorn", "--factory", "mailreports.main:create_app", "--host", "0.0.0.0", "--port", "8080"]
