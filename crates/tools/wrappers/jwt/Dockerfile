FROM python:3.13-slim

ENV NO_COLOR=1 ANSI_COLORS_DISABLED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && git clone https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && git -C /opt/jwt_tool checkout v2.3.0 \
    && pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/jwt_tool

RUN python3 jwt_tool.py eyJhbGciOiJIUzI1NiJ9.e30.x >/dev/null 2>&1 || true

ENTRYPOINT ["python3", "jwt_tool.py"]
