# fuxploider is frozen at this commit; run it on the interpreter/deps it supports. Python 3.13 removed
# stdlib it imports (cgi/imp/distutils), and urllib3 2.x broke its multipart upload
# (`TypeError: bytes-like object required, not _TemporaryFileWrapper`), so pin Python 3.11 and the
# pre-2.x request stack.
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && git clone https://github.com/almandin/fuxploider.git /opt/fuxploider \
    && git -C /opt/fuxploider checkout 75a81fffc784205b23a9237be7ef295ddbcc6ab2 \
    && pip install --no-cache-dir 'urllib3<2' 'requests<2.30' coloredlogs beautifulsoup4 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/fuxploider

ENTRYPOINT ["python", "fuxploider.py"]
