# syntax=docker/dockerfile:1

# --- build -------------------------------------------------------------------
# Build on the host platform and cross-compile: multi-arch images then need no
# QEMU for the Go toolchain, only the (static) runtime layer is target-arch.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src

# Module download first so source edits do not invalidate the dependency layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
        -ldflags "-s -w \
          -X github.com/hacktobeer/hexline/internal/version.Version=${VERSION} \
          -X github.com/hacktobeer/hexline/internal/version.Commit=${COMMIT} \
          -X github.com/hacktobeer/hexline/internal/version.BuildDate=${BUILD_DATE}" \
        -o /out/bbs ./cmd/bbs

# The runtime image is distroless and cannot create directories, so the data
# directory is prepared here and copied with the right ownership.
RUN mkdir -p /out/data

# --- runtime -----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# All state lives in one directory: SQLite database, host key, uploads,
# backups. Mount a volume here.
COPY --from=build --chown=nonroot:nonroot /out/data /data
COPY --from=build /out/bbs /usr/local/bin/bbs

ENV HEXLINE_DATA_DIR=/data \
    HEXLINE_SSH_ADDRESS=:2222 \
    HEXLINE_LOG_FORMAT=json

USER nonroot:nonroot
WORKDIR /data
VOLUME ["/data"]
EXPOSE 2222

ENTRYPOINT ["/usr/local/bin/bbs"]
# Override for one-shot commands, e.g.
#   docker run --rm -v hexline:/data hexline admin user create --handle sysop --role sysop
CMD ["serve"]
