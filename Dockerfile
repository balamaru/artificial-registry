FROM golang:1.26-alpine AS build
WORKDIR /src

# The pipe permits direct fallback on network errors, not only HTTP 404/410.
# Override with --build-arg GOPROXY=https://your-approved-go-proxy when needed.
ARG GOPROXY="https://proxy.golang.org|direct"
ENV GOPROXY=${GOPROXY} \
    GOSUMDB=sum.golang.org
# Direct module fetching requires Git; keep TLS certificate verification enabled.
RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN set -eu; \
    attempt=1; \
    until go mod download; do \
        if [ "$attempt" -ge 3 ]; then \
            echo "Module download failed after 3 attempts; check builder DNS, HTTPS access, and GOPROXY." >&2; \
            exit 1; \
        fi; \
        echo "Module download failed; retrying (attempt $((attempt + 1))/3)..." >&2; \
        sleep "$((attempt * 5))"; \
        attempt=$((attempt + 1)); \
    done; \
    go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags='-s -w' -o /registry ./cmd/registry
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /registry /registry
EXPOSE 8080
ENTRYPOINT ["/registry"]
