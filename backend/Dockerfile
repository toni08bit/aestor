# 3.11 matches Debian bookworm's python3-libtorrent ABI (cpython-311)
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-libtorrent \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Offline GeoLite2 Country DB for peer flags (no MaxMind account needed for this mirror)
RUN mkdir -p /usr/share/GeoIP \
    && curl -fsSL -o /usr/share/GeoIP/GeoLite2-Country.mmdb \
        https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb

WORKDIR /app

# Debian's python3-libtorrent installs into dist-packages
ENV PYTHONPATH=/usr/lib/python3/dist-packages
ENV GEOIP_DB_PATH=/usr/share/GeoIP/GeoLite2-Country.mmdb

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data/downloads /data/completed /keys

ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["sh", "-c", "uvicorn app.main:app --host ${HOST} --port ${PORT}"]
