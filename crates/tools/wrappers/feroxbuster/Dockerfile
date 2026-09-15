FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSLf https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.tar.gz \
       | tar -xz -C /usr/local/bin feroxbuster \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["feroxbuster"]
