FROM golang:1.27.1-bookworm AS build

RUN go install github.com/ffuf/ffuf/v2@v2.3.0

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /go/bin/ffuf /usr/local/bin/ffuf

ENTRYPOINT ["ffuf"]
