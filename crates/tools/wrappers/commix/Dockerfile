FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch v4.1 https://github.com/commixproject/commix.git /opt/commix

WORKDIR /opt/commix

ENTRYPOINT ["python", "commix.py"]
