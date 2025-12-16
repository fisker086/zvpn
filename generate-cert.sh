#!/bin/bash

# Generate self-signed certificate for SSL VPN
# For production, use a valid certificate from a CA

echo "Generating self-signed certificate for SSL VPN..."
echo "This is for testing only. Use a valid certificate in production."

# 创建 certs 目录（如果不存在）
mkdir -p ./certs

# 生成证书到 ./certs 目录
openssl req -x509 -newkey rsa:4096 \
  -keyout ./certs/key.pem \
  -out ./certs/cert.pem \
  -days 365 \
  -nodes \
  -subj "/C=CN/ST=State/L=City/O=ZVPN/CN=zvpn.local"

echo "✅ Certificate generated: ./certs/cert.pem"
echo "✅ Private key generated: ./certs/key.pem"
echo ""
echo "Certificates are ready to use. Config will automatically load them from ./certs/"

