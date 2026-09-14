FROM alpine:3.24
ARG CRATE_VERSION
ARG TARGETARCH
# Build provenance. Both default to empty so a plain `docker build` still works.
ARG GIT_COMMIT=""
ARG BUILT_AT=""

# Set maintainer metadata
LABEL maintainer="rustmailer <rustmailer.git@gmail.com>"
LABEL version="${CRATE_VERSION}"
LABEL description="Dockerized Bichon service"

# Standard annotations, so `docker inspect` on a running container is enough to
# find the commit it was built from.
LABEL org.opencontainers.image.title="Bichon"
LABEL org.opencontainers.image.description="A lightweight, high-performance Rust email archiver with WebUI"
LABEL org.opencontainers.image.source="https://github.com/rustmailer/bichon"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.version="${CRATE_VERSION}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILT_AT}"

# Set working directory
WORKDIR /opt/bichon

# Copy compiled binary (statically linked against musl, so it runs unmodified here)
COPY ${TARGETARCH}/bichon-server /opt/bichon/bichon-server
COPY ${TARGETARCH}/LICENSE /opt/bichon/


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
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates curl
# Create data directory
RUN mkdir -p /data

# Expose default ports
EXPOSE 15630

# Set volume and working directory
WORKDIR /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fs http://localhost:${BICHON_HTTP_PORT:-15630}/api/status || exit 1

CMD ["/opt/bichon/bichon-server"]
