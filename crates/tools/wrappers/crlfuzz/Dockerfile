FROM golang:1.25-alpine

RUN go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@v1.4.1

ENTRYPOINT ["crlfuzz"]
