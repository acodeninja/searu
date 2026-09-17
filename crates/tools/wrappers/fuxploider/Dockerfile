FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && git clone https://github.com/almandin/fuxploider.git /opt/fuxploider \
    && git -C /opt/fuxploider checkout 75a81fffc784205b23a9237be7ef295ddbcc6ab2 \
    && pip install --no-cache-dir -r /opt/fuxploider/requirements.txt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fuxploider

ENTRYPOINT ["python", "fuxploider.py"]
