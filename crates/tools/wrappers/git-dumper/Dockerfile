FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && pip install --no-cache-dir git-dumper==1.0.9 \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["git-dumper"]
