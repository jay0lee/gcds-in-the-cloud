# Multi-stage Cloud Run Job image bundling go-oauth-proxy + official Linux 64-bit GCDS
FROM golang:1.27-bookworm AS proxy-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/go-oauth-proxy ./cmd/go-oauth-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      gettext-base \
      python3 \
      procps \
    && rm -rf /var/lib/apt/lists/*

# Download and silently install official 64-bit Linux GCDS (includes bundled JRE in /opt/gcds/jre)
ARG GCDS_INSTALLER_URL="https://dl.google.com/dirsync/dirsync-linux64.sh"
RUN curl -fsSL "${GCDS_INSTALLER_URL}" -o /tmp/dirsync-linux64.sh \
    && sh /tmp/dirsync-linux64.sh -q -dir /opt/gcds \
    && rm -f /tmp/dirsync-linux64.sh

COPY --from=proxy-builder /out/go-oauth-proxy /usr/local/bin/go-oauth-proxy
COPY deploy/cloud-run/proxy-config.yaml.tmpl /etc/gcds/proxy-config.yaml.tmpl
COPY deploy/cloud-run/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN useradd -m -u 10001 gcds \
    && chmod +x /usr/local/bin/entrypoint.sh \
    && chown -R gcds:gcds /opt/gcds

USER gcds
WORKDIR /home/gcds
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
