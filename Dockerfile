# golift/codesign signerd image.
#
# Runs pcscd INSIDE the container: the host must not run its own pcscd on the
# same token (exclusive PC/SC access; pick one owner). Pass the YubiKey CCID
# interface in with --device; see docs/docker-usb.md for finding it safely.

FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=development
ARG REVISION
ARG BUILDDATE
ARG BRANCH
RUN CGO_ENABLED=0 go build -ldflags "-s -w \
        -X golift.io/version.Version=${VERSION} \
        -X golift.io/version.Revision=${REVISION} \
        -X golift.io/version.BuildDate=${BUILDDATE} \
        -X golift.io/version.Branch=${BRANCH}" \
        -o /out/signerd ./cmd/signerd \
    && CGO_ENABLED=0 go build -ldflags "-s -w \
        -X golift.io/version.Version=${VERSION} \
        -X golift.io/version.Revision=${REVISION} \
        -X golift.io/version.BuildDate=${BUILDDATE} \
        -X golift.io/version.Branch=${BRANCH}" \
        -o /out/codesign ./cmd/codesign

FROM debian:bookworm-slim

# pcscd + libccid reach the token; the ykcs11 binary package (source:
# yubico-piv-tool, https://packages.debian.org/bookworm/ykcs11) provides
# libykcs11.so; osslsigncode is the default signing backend; opensc supplies
# pkcs11-tool for the default PIN-free health probe.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libccid \
        opensc \
        osslsigncode \
        pcscd \
        ykcs11 \
    && rm -rf /var/lib/apt/lists/*

# Optional jsign backend (uncomment to bake it in):
#RUN apt-get update && apt-get install -y --no-install-recommends \
#        default-jre-headless curl \
#    && curl -fsSL -o /tmp/jsign.deb \
#        https://github.com/ebourg/jsign/releases/download/7.1/jsign_7.1_all.deb \
#    && dpkg -i /tmp/jsign.deb && rm -f /tmp/jsign.deb \
#    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/signerd /out/codesign /usr/local/bin/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENV SIGNERD_LISTEN=0.0.0.0:8750 \
    SIGNERD_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/libykcs11.so

EXPOSE 8750
ENTRYPOINT ["/entrypoint.sh"]
