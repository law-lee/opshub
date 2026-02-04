
# Build stage
FROM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/golang:1.25-alpine AS builder
# 设置 Go 环境变量
ENV GOPROXY=https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,direct \
    GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux
# Install build dependencies
# RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Copy go mod files
#COPY go.mod go.sum ./
# Download dependencies
RUN go mod download
# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o opshub main.go

# Runtime stage
FROM swr.cn-north-4.myhuaweicloud.com/ddn-k8s/docker.io/selectdb/alpine:latest

# Install ca-certificates, tzdata and kubectl
RUN apk --no-cache add ca-certificates tzdata curl && \
    curl -LO "https://dl.k8s.io/release/v1.29.0/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

# Set timezone
ENV TZ=Asia/Shanghai

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /build/opshub .

# Copy config template as default config
COPY config/config.yaml.example config/config.yaml

# Copy download script
COPY scripts/download-geoip.sh scripts/

# Create directories
RUN mkdir -p logs data && chmod +x scripts/download-geoip.sh

# Download GeoIP database at build time
RUN scripts/download-geoip.sh ./data

# Expose port
EXPOSE 9876

# Run the application
CMD ["./opshub", "server"]
