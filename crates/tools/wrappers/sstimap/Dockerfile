FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && git clone https://github.com/vladko312/SSTImap.git /opt/sstimap \
    && git -C /opt/sstimap checkout 1c27fdb4a4cc7d55b66fc0e16937ee7de7047490 \
    && pip install --no-cache-dir -r /opt/sstimap/requirements.txt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sstimap

ENTRYPOINT ["python", "sstimap.py"]
