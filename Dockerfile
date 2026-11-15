# syntax=docker/dockerfile:1
FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/bbs ./cmd/bbs

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /data
COPY --from=build /out/bbs /usr/local/bin/bbs
EXPOSE 2222
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/bbs"]
CMD ["serve", "--config", "/data/hexline.toml"]
