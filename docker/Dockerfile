FROM alpine:3.24
ARG CRATE_VERSION
ARG TARGETARCH
# Build provenance. Both default to empty so a plain `docker build` still works.
ARG GIT_COMMIT=""
ARG BUILT_AT=""
# GitHub links a ghcr.io package to the repository named here, and refuses to
# publish it under a repository that does not match. The workflows pass their
# own repository URL.
ARG IMAGE_SOURCE="https://github.com/nrosier/bichon"

# Set maintainer metadata
LABEL maintainer="rustmailer <rustmailer.git@gmail.com>"
LABEL version="${CRATE_VERSION}"
LABEL description="Dockerized Bichon service"

# Standard annotations, so `docker inspect` on a running container is enough to
# find the commit it was built from.
LABEL org.opencontainers.image.title="Bichon"
LABEL org.opencontainers.image.description="A lightweight, high-performance Rust email archiver with WebUI"
LABEL org.opencontainers.image.source="${IMAGE_SOURCE}"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.version="${CRATE_VERSION}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILT_AT}"

# Set working directory
WORKDIR /opt/bichon

# Copy compiled binary (statically linked against musl, so it runs unmodified here)
COPY ${TARGETARCH}/bichon-server /opt/bichon/bichon-server
COPY ${TARGETARCH}/LICENSE /opt/bichon/
# Third-party notices for every binary shipped in this image.
COPY ${TARGETARCH}/third-party-licenses/ /opt/bichon/third-party-licenses/


# cli tools
COPY ${TARGETARCH}/bichon-cli /usr/local/bin/bichon-cli
COPY ${TARGETARCH}/bichon-admin /usr/local/bin/bichon-admin

# Set permissions
RUN chmod +x /opt/bichon/bichon-server
RUN chmod +x /usr/local/bin/bichon-cli
RUN chmod +x /usr/local/bin/bichon-admin


# Upgrade base packages so already-installed libs (e.g. libssl3/libcrypto3)
# pick up fixes published after this alpine:3.22 tag was last rebuilt, then
# install ca-certificates to ensure HTTPS certificate verification works.
# tini becomes PID 1 so any process reparented to it (the healthcheck runs
# through a shell) is reaped instead of accumulating as a zombie.
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates curl tini
# Create data directory
RUN mkdir -p /data

# Expose default ports
EXPOSE 15630

# Set volume and working directory
WORKDIR /data

# --max-time stays below the healthcheck timeout so curl exits on its own
# instead of being orphaned when Docker kills a timed-out check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fs --max-time 4 http://localhost:${BICHON_HTTP_PORT:-15630}/api/status || exit 1

# tini as PID 1: reaps reparented children and forwards SIGTERM to the server.
ENTRYPOINT ["/sbin/tini","--"]
CMD ["/opt/bichon/bichon-server"]
