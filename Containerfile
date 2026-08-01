# syntax=docker/dockerfile:latest
# hadolint global shell=bash

ARG DEBIAN_VERSION=trixie
ARG DEBIAN_VERSION_NUMBER=13
ARG PROJECT=dragonfly-client-opengrep
ARG RUST_VERSION=1.91
ARG OPENGREP_VERSION=1.26.0
ARG OPENGREP_SHA256=40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26

FROM rust:$RUST_VERSION-$DEBIAN_VERSION AS opengrep-binary
ARG OPENGREP_SHA256
ARG OPENGREP_VERSION
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN <<EOT
#!/usr/bin/env bash
set -euo pipefail

curl --fail --location --silent --show-error \
  "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86" \
  --output /opengrep
printf '%s  /opengrep\n' "${OPENGREP_SHA256}" > /tmp/opengrep.sha256
sha256sum --check --strict /tmp/opengrep.sha256
chmod 0755 /opengrep
EOT

FROM rust:$RUST_VERSION-$DEBIAN_VERSION AS build
ARG PROJECT
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /app

COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=opengrep-rust-target,target=/app/target \
  <<EOT
#!/usr/bin/env bash
set -euo pipefail

mkdir src
printf 'fn main() {}\n' > src/main.rs
cargo build --locked --release
rm src/main.rs "target/release/deps/${PROJECT//-/_}"*
EOT

COPY src src

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=opengrep-rust-target,target=/app/target \
  cargo build --locked --release --bin "$PROJECT" \
  && cp "/app/target/release/$PROJECT" "/app/$PROJECT"

FROM gcr.io/distroless/cc-debian$DEBIAN_VERSION_NUMBER:nonroot AS release
ARG PROJECT
WORKDIR /app

COPY --from=build "/app/$PROJECT" "/app/$PROJECT"
COPY --from=opengrep-binary /opengrep /usr/local/bin/opengrep

ENTRYPOINT ["./dragonfly-client-opengrep"]
