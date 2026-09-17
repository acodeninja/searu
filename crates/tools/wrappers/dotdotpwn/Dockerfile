FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       git ca-certificates perl libwww-perl libhttp-lite-perl libswitch-perl libterm-readkey-perl \
    && git clone https://github.com/wireghoul/dotdotpwn.git /opt/dotdotpwn \
    && git -C /opt/dotdotpwn checkout 1d3af99d7de1ab7f2a321934891ecd3ff1a02734 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/dotdotpwn

# dotdotpwn returns a non-zero exit tied to its run; searu signals a clean run through exit 0 and
# reports findings separately, so normalise the exit code here.
ENTRYPOINT ["/bin/sh", "-c", "perl dotdotpwn.pl \"$@\"; exit 0", "--"]
