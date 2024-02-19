#FROM rust:1.75 AS builder
FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder

USER root
RUN mkdir -p /src/nats2jetstream/target /usr/local/cargo && \
    chown nobody: /src/nats2jetstream/target /usr/local/cargo

ENV CARGO_HOME=/usr/local/cargo

USER nobody
WORKDIR /src/nats2jetstream

RUN cargo --version
RUN cargo install cargo-auditable cargo-audit

COPY . /src/nats2jetstream

RUN cargo update
RUN cargo fetch --verbose
#RUN rustup target add x86_64-unknown-linux-musl

ARG GIT_VERSION
#RUN cargo build --features=version-from-env
#RUN cargo test --features=version-from-env
#RUN cargo bench --features=version-from-env
RUN cargo auditable build --features=version-from-env \
      --release --target x86_64-unknown-linux-musl
RUN test "$(echo $(ldd target/x86_64-unknown-linux-musl/release/nats2jetstream))" = "statically linked"

FROM scratch
COPY --from=builder /src/nats2jetstream/target/x86_64-unknown-linux-musl/release/nats2jetstream /nats2jetstream
