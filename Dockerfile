# syntax=docker/dockerfile:1

# --- Build -------------------------------------------------------------------
# Runs on the builder's own platform and cross-compiles, so multi-arch images
# don't need QEMU. The binary is static (no cgo).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/secure-input .

# --- Runtime -----------------------------------------------------------------
# distroless/static ships CA certificates and a nonroot user, and nothing else.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secure-input /usr/local/bin/secure-input
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/secure-input"]
CMD ["serve", "--addr", ":8787"]
