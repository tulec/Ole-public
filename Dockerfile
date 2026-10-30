FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
ARG REPOSITORY_URL=https://github.com/openai/unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN apk add --no-cache ca-certificates tzdata

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/ole-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
ARG REPOSITORY_URL=https://github.com/openai/unknown

WORKDIR /app

LABEL org.opencontainers.image.title="Ole Server" \
      org.opencontainers.image.description="Ole control plane, STUN, relay, and API server." \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.source=$REPOSITORY_URL

COPY --from=build /out/ole-server /app/ole-server
COPY internal/store/postgres/migrations /app/internal/store/postgres/migrations
COPY docs/openapi.yaml /app/docs/openapi.yaml

EXPOSE 8080
EXPOSE 3478/udp
EXPOSE 3479/udp

ENTRYPOINT ["/app/ole-server"]
