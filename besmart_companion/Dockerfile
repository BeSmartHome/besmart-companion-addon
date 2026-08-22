FROM alpine:3.22

RUN apk add --no-cache \
    python3 \
    py3-pip \
    curl \
    tailscale

RUN pip3 install --no-cache-dir --break-system-packages \
    pyhpke==0.6.3

COPY app.py /app/app.py
COPY run.sh /run.sh

RUN chmod +x /run.sh

CMD ["/run.sh"]
