# syntax=docker/dockerfile:1.7
# Reproducible, Deterministic Proof of Geography TEE Binary & Measurement Builder
# Anyone can run this Dockerfile to reproduce the exact SHA-256 / BLAKE3 binary digests
# used to verify AMD SEV-SNP, Intel TDX, and AWS Nitro workload measurements.

FROM rust:1.83-bookworm AS builder

ENV SOURCE_DATE_EPOCH=1700000000 \
    TZ=UTC \
    LC_ALL=C \
    CARGO_INCREMENTAL=0 \
    CARGO_NET_RETRY=5 \
    RUSTFLAGS="--remap-path-prefix=/src=/pog -C debuginfo=0 -C strip=symbols -C codegen-units=1"

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release --locked --bins \
    && mkdir -p /out \
    && cp target/release/pog-anchor target/release/pog-prover target/release/pog-cli /out/ \
    && touch -d "@${SOURCE_DATE_EPOCH}" /out/pog-anchor /out/pog-prover /out/pog-cli \
    && cd /out \
    && sha256sum pog-anchor pog-prover pog-cli > SHA256SUMS

# Minimal immutable runtime image (zero shell/package-manager bloat inside TEE!)
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /out/pog-anchor /usr/local/bin/pog-anchor
COPY --from=builder /out/pog-prover /usr/local/bin/pog-prover
COPY --from=builder /out/pog-cli /usr/local/bin/pog-cli
COPY --from=builder /out/SHA256SUMS /etc/pog/SHA256SUMS

ENTRYPOINT ["/usr/local/bin/pog-anchor"]
