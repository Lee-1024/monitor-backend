# ============================================
# Monitor Backend - 多阶段构建
# ============================================

# 阶段一：构建
FROM golang:1.24-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o monitor-backend .

# 阶段二：运行
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

RUN adduser -D -g "" appuser
WORKDIR /app

COPY --from=builder /build/monitor-backend .

USER appuser

# 默认配置文件路径，可通过 -v 挂载 config.yaml 覆盖
ENV CONFIG_PATH=config.yaml

# gRPC 与 HTTP 端口
EXPOSE 50051 8080

ENTRYPOINT ["./monitor-backend"]
