# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
ARG XRAY_VERSION=v1.8.24
WORKDIR /src
COPY main.go .
RUN go mod init tgproxy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tgproxy .
RUN apk add --no-cache unzip wget \
 && wget -q "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" -O /x.zip \
 && unzip -j /x.zip xray -d /out \
 && chmod +x /out/xray

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/xray /xray
COPY --from=build /out/tgproxy /tgproxy
ENV GOGC=50 GOMEMLIMIT=64MiB
EXPOSE 10000
ENTRYPOINT ["/tgproxy"]
