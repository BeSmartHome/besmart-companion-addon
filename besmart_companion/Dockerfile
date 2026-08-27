FROM alpine:3.22

ARG TARGETARCH
ARG CLOUDFLARED_VERSION=2026.8.2
ENV BESMART_CLOUDFLARED_BIN=/usr/local/bin/cloudflared
ENV SOSYNC_COMPANION_VERSION=1.0.22
ENV SOSYNC_COMPANION_BUILD=1.0.22-secure-remote-e2ee-dataplane-v1

RUN apk add --no-cache \
    python3 \
    py3-pip \
    curl \
    ca-certificates \
    tailscale

RUN set -eux; \
    case "${TARGETARCH:-}" in \
      amd64) cloudflared_arch="amd64" ;; \
      arm64) cloudflared_arch="arm64" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH:-unset}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL \
      "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-${cloudflared_arch}" \
      -o /usr/local/bin/cloudflared; \
    chmod 0755 /usr/local/bin/cloudflared; \
    /usr/local/bin/cloudflared --version

RUN pip3 install --no-cache-dir --break-system-packages \
    pyhpke==0.6.3

COPY app.py /app/app.py
COPY run.sh /run.sh

RUN chmod +x /run.sh

CMD ["/run.sh"]
