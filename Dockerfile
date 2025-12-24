FROM alpine:latest

RUN apk update && apk upgrade && \
    apk add --no-cache \
    bash \
    bind-tools \
    iproute2 \
    iptables \
    openvpn \
    curl

COPY entry.sh /usr/local/bin/entry.sh
COPY killswitch.sh /usr/local/bin/killswitch.sh
COPY check_wan_ip_health /usr/local/bin/check_wan_ip_health

RUN chmod +x /usr/local/bin/entry.sh \
           /usr/local/bin/killswitch.sh \
           /usr/local/bin/check_wan_ip_health

ENV KILL_SWITCH=on

ENTRYPOINT [ "entry.sh" ]

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=2 \
  CMD /usr/local/bin/check_wan_ip_health && pgrep openvpn
