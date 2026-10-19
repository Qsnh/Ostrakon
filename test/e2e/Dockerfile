# End-to-end test image: real nftables, the ostrakon daemon and a fake Jev.
# Built by e2e.sh, which puts the linux binaries in bin/ first. Run it with
# --privileged so nft can manage the kernel's firewall.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

COPY bin/ostrakon bin/fakejev /usr/local/bin/
COPY run.sh /usr/local/bin/run.sh

CMD ["bash", "/usr/local/bin/run.sh"]
