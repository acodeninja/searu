FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git perl libnet-ssleay-perl libxml-writer-perl ca-certificates \
    && git clone --depth 1 --branch 2.6.1 https://github.com/sullo/nikto.git /opt/nikto \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/opt/nikto/program/nikto.pl"]
