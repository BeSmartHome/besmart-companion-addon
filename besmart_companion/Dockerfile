FROM alpine:3.22

RUN apk add --no-cache \
    python3 \
    curl \
    tailscale

COPY app.py /app/app.py
COPY run.sh /run.sh

RUN chmod +x /run.sh

CMD ["/run.sh"]
