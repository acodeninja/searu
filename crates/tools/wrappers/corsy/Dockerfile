FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && git clone https://github.com/s0md3v/Corsy.git /opt/corsy \
    && git -C /opt/corsy checkout 2985ae24da524ba6905d36bfbadca7fe71a9f199 \
    && pip install --no-cache-dir requests \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/corsy

ENTRYPOINT ["python", "corsy.py"]
