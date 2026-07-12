# Container image for the bmvs-verifier CLI (bootstrap plan Phase 2 item 4).
#
# Two stages: build on the pinned stable Rust (Alpine/musl for a fully
# static binary), then ship the lone binary on `scratch` — no shell, no
# libc, no package manager; the image *is* the verifier. Publishing the
# image is a release act performed by Rich (D9); CI only builds it.
#
# Build:  docker build -t bmvs-verifier .
# Run:    docker run --rm -v /path/to/record:/record:ro bmvs-verifier verify /record

FROM rust:1.97.0-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p bmvs-verifier

FROM scratch
COPY --from=build /src/target/release/bmvs-verifier /bmvs-verifier
ENTRYPOINT ["/bmvs-verifier"]
