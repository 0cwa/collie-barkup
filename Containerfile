FROM docker.io/library/rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
 && mkdir -p /out/data && chown 65532:65532 /out/data \
 && cp target/release/collie-barkup /out/collie-barkup
FROM scratch
COPY --from=build /out/collie-barkup /collie-barkup
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME ["/data"]
ENV BARKUP_DATA=/data BARKUP_BIND=0.0.0.0:8082
USER 65532:65532
EXPOSE 8082
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/collie-barkup","healthcheck"]
ENTRYPOINT ["/collie-barkup"]
CMD ["serve"]
