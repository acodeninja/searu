FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch 1.10.9 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

WORKDIR /opt/sqlmap

ENTRYPOINT ["python", "sqlmap.py"]
