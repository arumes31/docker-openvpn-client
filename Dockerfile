FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache \
    bash=5.3.9-r1 \
    bind-tools=9.20.26-r0 \
    curl=8.21.0-r0 \
    iproute2=7.0.0-r0 \
    iptables=1.8.13-r0 \
    libcrypto3=3.5.8-r0 \
    libssl3=3.5.8-r0 \
    openvpn=2.7.5-r0

COPY entry.sh /usr/local/bin/entry.sh
COPY killswitch.sh /usr/local/bin/killswitch.sh
COPY check_wan_ip_health /usr/local/bin/check_wan_ip_health

RUN chmod +x /usr/local/bin/entry.sh \
           /usr/local/bin/killswitch.sh \
           /usr/local/bin/check_wan_ip_health

ENV KILL_SWITCH=on

ENTRYPOINT ["entry.sh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=2 \
  CMD ["/bin/sh", "-c", "/usr/local/bin/check_wan_ip_health && pgrep openvpn"]
