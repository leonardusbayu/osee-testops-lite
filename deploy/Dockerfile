FROM golang:1.27.1-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66 AS build
WORKDIR /src
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-buildvcs=false GOPROXY=off GOSUMDB=off GOMODCACHE=/modules
COPY --from=public_modules . /modules
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY db ./db
RUN --network=none set -eu; go mod verify; for name in web worker migrate candidatectl; do go build -trimpath -o /out/$name ./cmd/$name; done
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
COPY --from=build /out/ /app/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/web"]
