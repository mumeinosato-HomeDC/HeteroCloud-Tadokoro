FROM rust:1.96.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin tadokoro-api

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin tadokoro
COPY --from=build /src/target/release/tadokoro-api /usr/local/bin/tadokoro-api
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/tadokoro-api"]
