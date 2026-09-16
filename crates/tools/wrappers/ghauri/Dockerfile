FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && pip install --no-cache-dir git+https://github.com/r0oth3x49/ghauri.git@1.4.3 \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["ghauri"]
