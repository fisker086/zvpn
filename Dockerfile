FROM node:20-alpine AS frontend-builder
WORKDIR /frontend
COPY ui/package*.json ./
RUN npm install
COPY ui ./
# Use build:prod to skip vue-tsc type-check in container (keeps CI fast)
RUN npm run build:prod

# 使用 Rocky Linux 9 作为构建基础镜像
# Rocky Linux 9 内核 5.14+，完全支持 eBPF TCX egress (内核 5.19+)，对 eBPF 开发更友好
FROM rockylinux:9 AS builder

# 设置非交互式安装
ENV DNF_FRONTEND=noninteractive

# 启用 CRB 仓库并安装基础依赖（包括 Go）
RUN dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs \
        dnf-plugins-core && \
    dnf config-manager --set-enabled crb && \
    dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs \
        ca-certificates \
        clang llvm \
        libbpf-devel elfutils-libelf-devel \
        kernel-headers kernel-devel \
        zlib-devel \
        gcc gcc-c++ make git \
        golang \
        glibc-devel.i686 || echo "32-bit glibc-devel not available, continuing..." && \
    update-ca-trust extract && \
    go version && \
    dnf clean all && \
    rm -rf /var/cache/dnf /tmp/* /var/tmp/*

WORKDIR /app
ENV GO111MODULE=on 
ENV GOPROXY=https://goproxy.cn
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 准备 eBPF 编译环境（处理头文件路径）
# 使用容器内可用的内核头文件，而不是 uname -r 的结果
RUN if [ -d "/usr/src/kernels" ] && [ "$(ls -A /usr/src/kernels 2>/dev/null)" ]; then \
        KERNEL_HEADERS_DIR=$(ls -d /usr/src/kernels/* 2>/dev/null | head -1); \
    elif [ -d "/usr/src/kernel-headers" ]; then \
        KERNEL_HEADERS_DIR=/usr/src/kernel-headers; \
    else \
        KERNEL_HEADERS_DIR=/usr/include; \
    fi && \
    mkdir -p /usr/include/asm && \
    if [ -f ${KERNEL_HEADERS_DIR}/arch/x86/include/asm/bitsperlong.h ]; then \
        ln -sf ${KERNEL_HEADERS_DIR}/arch/x86/include/asm/bitsperlong.h /usr/include/asm/; \
    elif [ -f /usr/include/x86_64-linux-gnu/asm/bitsperlong.h ]; then \
        ln -sf /usr/include/x86_64-linux-gnu/asm/bitsperlong.h /usr/include/asm/; \
    fi && \
    echo "Prepared eBPF compilation environment with headers from: ${KERNEL_HEADERS_DIR}"

# 编译 eBPF XDP 程序（使用容器内可用的内核头文件）
# 注意：容器内的内核头文件版本可能与主机内核版本不同，使用容器内实际可用的版本
# 对于 eBPF 编译，优先使用 UAPI 头文件，避免内核内部实现
RUN cd /app/vpn/ebpf && \
    if [ -d "/usr/src/kernels" ] && [ "$(ls -A /usr/src/kernels 2>/dev/null)" ]; then \
        KERNEL_HEADERS_DIR=$(ls -d /usr/src/kernels/* 2>/dev/null | head -1); \
        echo "Using kernel headers from: ${KERNEL_HEADERS_DIR}"; \
    elif [ -d "/usr/src/kernel-headers" ]; then \
        KERNEL_HEADERS_DIR=/usr/src/kernel-headers; \
        echo "Using kernel headers from: ${KERNEL_HEADERS_DIR}"; \
    elif [ -d "/usr/include/linux" ]; then \
        KERNEL_HEADERS_DIR=/usr/include; \
        echo "Using system headers from: ${KERNEL_HEADERS_DIR}"; \
    else \
        echo "Error: No kernel headers found"; \
        echo "Available directories:"; \
        ls -la /usr/src/ 2>/dev/null || echo "No /usr/src directory"; \
        exit 1; \
    fi && \
    CGO_ENABLED=1 GOPACKAGE=ebpf go run github.com/cilium/ebpf/cmd/bpf2go \
        -cc clang \
        -cflags "-O2 -g -target bpf -mllvm -bpf-stack-size=16384 -D__BPF__ -D__TARGET_ARCH_x86 -U__KERNEL__ -D__BPF_TRACING__ -D__no_sanitize_or_inline=inline -D__no_kasan_or_inline=inline -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -Wno-macro-redefined -Wno-incompatible-library-redeclaration -Wno-#warnings -include /app/vpn/ebpf/src/bpf_compat.h -I/usr/include -I${KERNEL_HEADERS_DIR}/include/uapi -I${KERNEL_HEADERS_DIR}/arch/x86/include/uapi -I${KERNEL_HEADERS_DIR}/arch/x86/include/generated/uapi -I${KERNEL_HEADERS_DIR}/include/generated/uapi -I${KERNEL_HEADERS_DIR}/include -I${KERNEL_HEADERS_DIR}/arch/x86/include -I${KERNEL_HEADERS_DIR}/arch/x86/include/generated" \
        -target bpf \
        -no-strip -no-global-types \
        -go-package ebpf xdp ./src/xdp_program.c

# 编译 eBPF TC NAT 程序（使用容器内可用的内核头文件）
RUN cd /app/vpn/ebpf && \
    if [ -d "/usr/src/kernels" ] && [ "$(ls -A /usr/src/kernels 2>/dev/null)" ]; then \
        KERNEL_HEADERS_DIR=$(ls -d /usr/src/kernels/* 2>/dev/null | head -1); \
        echo "Using kernel headers from: ${KERNEL_HEADERS_DIR}"; \
    elif [ -d "/usr/src/kernel-headers" ]; then \
        KERNEL_HEADERS_DIR=/usr/src/kernel-headers; \
        echo "Using kernel headers from: ${KERNEL_HEADERS_DIR}"; \
    elif [ -d "/usr/include/linux" ]; then \
        KERNEL_HEADERS_DIR=/usr/include; \
        echo "Using system headers from: ${KERNEL_HEADERS_DIR}"; \
    else \
        echo "Error: No kernel headers found"; \
        echo "Available directories:"; \
        ls -la /usr/src/ 2>/dev/null || echo "No /usr/src directory"; \
        exit 1; \
    fi && \
    CGO_ENABLED=1 GOPACKAGE=ebpf go run github.com/cilium/ebpf/cmd/bpf2go \
        -cc clang \
        -cflags "-O2 -g -target bpf -mllvm -bpf-stack-size=16384 -D__BPF__ -D__TARGET_ARCH_x86 -U__KERNEL__ -D__BPF_TRACING__ -D__no_sanitize_or_inline=inline -D__no_kasan_or_inline=inline -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -Wno-macro-redefined -Wno-incompatible-library-redeclaration -Wno-#warnings -include /app/vpn/ebpf/src/bpf_compat.h -I/usr/include -I${KERNEL_HEADERS_DIR}/include/uapi -I${KERNEL_HEADERS_DIR}/arch/x86/include/uapi -I${KERNEL_HEADERS_DIR}/arch/x86/include/generated/uapi -I${KERNEL_HEADERS_DIR}/include/generated/uapi -I${KERNEL_HEADERS_DIR}/include -I${KERNEL_HEADERS_DIR}/arch/x86/include -I${KERNEL_HEADERS_DIR}/arch/x86/include/generated" \
        -target bpf \
        -no-strip -no-global-types \
        -go-package ebpf tc_nat ./src/tc_nat.c
# 编译主程序
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-w -s" -tags netgo,osusergo,ebpf -o /zvpn ./main.go

# ============ 运行阶段：使用 Rocky Linux 9 ============
# Rocky Linux 9 对 eBPF 支持更好，内核更新，完全支持 eBPF TC egress
FROM rockylinux:9

# 设置非交互式安装
ENV DNF_FRONTEND=noninteractive

RUN dnf install -y --setopt=install_weak_deps=False --setopt=tsflags=nodocs \
        ca-certificates \
        libbpf \
        iproute kmod bash openssl nc wget \
        tcpdump \
        iputils  \
        kernel-tools || true && \
    dnf clean all && \
    rm -rf /var/cache/dnf /tmp/* /var/tmp/*

# Rocky Linux 9 内核更新，完全支持 eBPF TC egress (内核 5.19+)
# 可以使用高性能的 eBPF TC egress NAT

# 复制编译好的二进制和文件（合并命令减少层数）
WORKDIR /app
COPY --from=builder /zvpn /app/zvpn
COPY --from=builder /app/vpn/ebpf/ /app/vpn/ebpf/
COPY --from=frontend-builder /frontend/dist /app/web
COPY config.yaml generate-cert.sh docker-entrypoint.sh /app/
RUN chmod +x /app/generate-cert.sh /app/docker-entrypoint.sh && \
    mkdir -p /app/certs /app/data 

# 环境变量
ENV GIN_MODE=release \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=18080 \
    VPN_OPENCONNECT_PORT=443 \
    VPN_DTLS_PORT=443 \
    VPN_ENABLE_DTLS=true \
    VPN_NETWORK=10.8.0.0/24 \
    VPN_INTERFACE=zvpn0 \
    VPN_EGRESS_INTERFACE=eth0 \
    VPN_ENABLE_OPENCONNECT=true \
    VPN_ENABLE_CUSTOM_PROTOCOL=false

VOLUME ["/sys/fs/bpf"]
EXPOSE 18080 443 443/udp

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:18080/api/v1/health || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["/app/zvpn"]

