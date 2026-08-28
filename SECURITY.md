# Security policy

The latest image and current default branch receive security fixes. Report
vulnerabilities privately through GitHub's **Security** tab; do not publish VPN
credentials, configuration files, or exploit details in an issue.

## Runtime security model

This container must configure the tunnel and its network namespace, so it intentionally
requires `/dev/net/tun` and `CAP_NET_ADMIN`. It does not require `--privileged`, host
networking, a Docker socket, `CAP_SYS_ADMIN`, or `CAP_SYS_MODULE`. Deploy with every
capability dropped except `NET_ADMIN`, `no-new-privileges`, a read-only root filesystem,
and VPN configuration mounted read-only. Treat any broader grant as a security defect.
