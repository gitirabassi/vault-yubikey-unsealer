FROM alpine:latest as rage
RUN apk add --update --no-cache curl tar zip 
RUN curl -O -L https://github.com/str4d/rage/releases/download/v0.7.1/rage-v0.7.1-x86_64-linux.tar.gz && \
    tar xvf rage-v0.7.1-x86_64-linux.tar.gz

RUN curl -O -L https://github.com/str4d/age-plugin-yubikey/releases/download/v0.1.0/age-plugin-yubikey-v0.1.0-x86_64-linux.tar.gz && \
    tar xvf age-plugin-yubikey-v0.1.0-x86_64-linux.tar.gz 

FROM golang:alpine AS builder

RUN mkdir /app
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-extldflags=-static' -o /vault-manager ./main.go
RUN chmod +x /vault-manager

FROM debian:stable-slim
RUN apt-get update && apt-get install libpcsclite1 -y
COPY --from=builder /vault-manager /vault-manager
COPY config.yaml /config.yaml
COPY --from=rage /rage/rage /rage/rage-keygen /rage/rage-mount /usr/bin/
COPY --from=rage /age-plugin-yubikey/age-plugin-yubikey /usr/bin/

ENTRYPOINT ["/vault-manager"]
