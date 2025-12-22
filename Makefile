# ZVPN Makefile
# 用于构建、运行和管理 ZVPN 项目

# 变量定义
BINARY_NAME=zvpn
MAIN_PACKAGE=./main.go
BUILD_DIR=build
GO_VERSION=1.24
VERSION?=dev
BUILD_TIME=$(shell date +%Y-%m-%d_%H:%M:%S)
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_TAG=$(shell git describe --tags --exact-match 2>/dev/null || echo "")
DOCKER_IMAGE=$(BINARY_NAME)
DOCKER_TAG?=$(VERSION)
DOCKER_REGISTRY?=

# Go 构建标志
# -trimpath: 移除文件系统路径，使构建可重现
# -s -w: 减小二进制大小（去除符号表和调试信息）
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT) -s -w"
GO_BUILD=go build -trimpath $(LDFLAGS)
GO_BUILD_STATIC=CGO_ENABLED=0 $(GO_BUILD) -tags netgo,osusergo
GO_BUILD_EBPF=CGO_ENABLED=1 $(GO_BUILD) -tags netgo,osusergo,ebpf

# 默认目标
.DEFAULT_GOAL := help

.PHONY: help
help: ## 显示帮助信息
	@echo "ZVPN Makefile 命令："
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## 构建项目（当前平台）
	@echo "构建 $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)"

.PHONY: build-linux
build-linux: ## 构建 Linux 版本 (amd64)
	@echo "构建 Linux amd64 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO_BUILD_EBPF) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

.PHONY: build-linux-arm64
build-linux-arm64: ## 构建 Linux ARM64 版本
	@echo "构建 Linux arm64 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 $(GO_BUILD_EBPF) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_PACKAGE)
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64"

.PHONY: build-windows
build-windows: ## 构建 Windows 版本 (amd64)
	@echo "构建 Windows amd64 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GO_BUILD_STATIC) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe"

.PHONY: build-darwin
build-darwin: ## 构建 macOS 版本 (amd64)
	@echo "构建 macOS amd64 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GO_BUILD_STATIC) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PACKAGE)
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64"

.PHONY: build-darwin-arm64
build-darwin-arm64: ## 构建 macOS ARM64 版本 (Apple Silicon)
	@echo "构建 macOS arm64 版本..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 $(GO_BUILD_STATIC) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64"

.PHONY: build-all
build-all: build-linux build-linux-arm64 build-windows build-darwin build-darwin-arm64 ## 构建所有平台版本

.PHONY: run
run: ## 运行项目（需要先构建）
	@if [ ! -f $(BUILD_DIR)/$(BINARY_NAME) ]; then \
		echo "请先运行 'make build' 构建项目"; \
		exit 1; \
	fi
	@echo "运行 $(BINARY_NAME)..."
	@sudo $(BUILD_DIR)/$(BINARY_NAME)

.PHONY: run-dev
run-dev: ## 开发模式运行（直接运行，不构建）
	@echo "开发模式运行..."
	@go run $(MAIN_PACKAGE)

.PHONY: deps
deps: ## 下载依赖
	@echo "下载 Go 依赖..."
	@go mod download
	@go mod tidy
	@echo "依赖下载完成"

.PHONY: deps-update
deps-update: ## 更新依赖到最新版本
	@echo "更新依赖..."
	@go get -u ./...
	@go mod tidy
	@echo "依赖更新完成"

.PHONY: cert
cert: ## 生成 TLS 证书
	@echo "生成 TLS 证书..."
	@if [ -f generate-cert.sh ]; then \
		chmod +x generate-cert.sh && ./generate-cert.sh; \
	else \
		echo "使用 openssl 生成证书..."; \
		mkdir -p certs; \
		openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
			-subj "/C=CN/ST=State/L=City/O=ZVPN/CN=zvpn.local"; \
	fi
	@echo "证书生成完成: certs/server.crt, certs/server.key"

.PHONY: clean
clean: ## 清理构建文件
	@echo "清理构建文件..."
	@rm -rf $(BUILD_DIR)
	@go clean -cache -testcache
	@rm -f coverage.out coverage.html
	@echo "清理完成"

.PHONY: clean-all
clean-all: clean ## 清理所有文件（包括数据库、证书和测试文件）
	@echo "清理所有文件..."
	@rm -f *.db *.db-shm *.db-wal
	@rm -f *.pem *.key *.crt
	@rm -rf ./data/*
	@rm -rf ./certs/*
	@echo "清理完成"

.PHONY: test
test: ## 运行测试
	@echo "运行测试..."
	@go test -v ./...

.PHONY: test-race
test-race: ## 运行测试并检测竞态条件
	@echo "运行竞态检测测试..."
	@go test -v -race ./...

.PHONY: test-bench
test-bench: ## 运行基准测试
	@echo "运行基准测试..."
	@go test -v -bench=. -benchmem ./...

.PHONY: test-coverage
test-coverage: ## 运行测试并生成覆盖率报告
	@echo "运行测试并生成覆盖率报告..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"
	@echo "覆盖率统计:"
	@go tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt: ## 格式化代码
	@echo "格式化代码..."
	@go fmt ./...
	@echo "格式化完成"

.PHONY: lint
lint: ## 运行代码检查（需要安装 golangci-lint）
	@echo "运行代码检查..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint 未安装，跳过检查"; \
		echo "安装: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

.PHONY: vet
vet: ## 运行 go vet
	@echo "运行 go vet..."
	@go vet ./...

.PHONY: install
install: build ## 安装到系统路径（需要 root 权限）
	@echo "安装 $(BINARY_NAME) 到 /usr/local/bin..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "安装完成"

.PHONY: uninstall
uninstall: ## 从系统路径卸载
	@echo "卸载 $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "卸载完成"

.PHONY: docker-build
docker-build: ## 使用 Docker 构建镜像
	@echo "使用 Docker 构建镜像..."
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@if [ -n "$(GIT_TAG)" ]; then \
		docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest; \
		echo "已标记为 latest: $(DOCKER_IMAGE):latest"; \
	fi
	@echo "Docker 镜像构建完成: $(DOCKER_IMAGE):$(DOCKER_TAG)"

.PHONY: docker-push
docker-push: docker-build ## 推送 Docker 镜像到仓库
	@if [ -z "$(DOCKER_REGISTRY)" ]; then \
		echo "错误: 请设置 DOCKER_REGISTRY 变量"; \
		exit 1; \
	fi
	@echo "推送 Docker 镜像..."
	@docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	@docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	@if [ -n "$(GIT_TAG)" ]; then \
		docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest; \
		docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest; \
	fi
	@echo "镜像推送完成"

.PHONY: docker-run
docker-run: ## 使用 Docker 运行容器
	@echo "使用 Docker 运行容器..."
	@docker run --rm -it \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		--cap-add=SYS_ADMIN \
		--cap-add=BPF \
		--device=/dev/net/tun \
		-v /sys/fs/bpf:/sys/fs/bpf:rw \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: docker-stop
docker-stop: ## 停止所有 Docker 容器
	@echo "停止 Docker 容器..."
	@docker-compose down || true
	@docker stop $(shell docker ps -q --filter "ancestor=$(DOCKER_IMAGE):$(DOCKER_TAG)" 2>/dev/null) 2>/dev/null || true
	@echo "容器已停止"

.PHONY: docker-clean
docker-clean: docker-stop ## 清理 Docker 镜像和容器
	@echo "清理 Docker 资源..."
	@docker-compose down -v 2>/dev/null || true
	@docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true
	@docker rmi $(DOCKER_IMAGE):latest 2>/dev/null || true
	@echo "清理完成"

.PHONY: docker-compose-up
docker-compose-up: ## 使用 docker-compose 启动服务
	@echo "启动 docker-compose 服务..."
	@docker-compose up -d
	@echo "服务已启动，使用 'make docker-compose-logs' 查看日志"

.PHONY: docker-compose-down
docker-compose-down: ## 停止 docker-compose 服务
	@echo "停止 docker-compose 服务..."
	@docker-compose down
	@echo "服务已停止"

.PHONY: docker-compose-logs
docker-compose-logs: ## 查看 docker-compose 日志
	@docker-compose logs -f

.PHONY: docker-compose-restart
docker-compose-restart: docker-compose-down docker-compose-up ## 重启 docker-compose 服务

.PHONY: docker-compose-build
docker-compose-build: ## 使用 docker-compose 构建镜像
	@echo "使用 docker-compose 构建镜像..."
	@docker-compose build
	@echo "构建完成"

.PHONY: mod-verify
mod-verify: ## 验证 Go 模块依赖
	@echo "验证 Go 模块..."
	@go mod verify
	@go mod tidy
	@echo "模块验证完成"

.PHONY: check
check: fmt vet lint test ## 运行所有检查（格式化、vet、lint、测试）

.PHONY: check-all
check-all: check test-race test-coverage ## 运行完整检查（包括竞态检测和覆盖率）

.PHONY: dev
dev: deps cert run-dev ## 开发环境设置（下载依赖、生成证书、运行）

.PHONY: watch
watch: ## 监控文件变化并自动重新运行（需要安装 air: go install github.com/cosmtrek/air@latest）
	@if command -v air >/dev/null 2>&1; then \
		air; \
	else \
		echo "air 未安装，使用 'go install github.com/cosmtrek/air@latest' 安装"; \
		echo "或者使用 'make run-dev' 手动运行"; \
	fi

.PHONY: release
release: clean check-all build-all ## 发布版本（清理、完整检查、构建所有平台）

.PHONY: release-docker
release-docker: clean check docker-build ## 发布 Docker 版本（清理、检查、构建镜像）

.PHONY: version
version: ## 显示版本信息
	@echo "版本信息:"
	@echo "  Version:   $(VERSION)"
	@echo "  Git Commit: $(GIT_COMMIT)"
	@echo "  Build Time: $(BUILD_TIME)"
	@echo "  Go Version: $(GO_VERSION)"
	@if [ -n "$(GIT_TAG)" ]; then \
		echo "  Git Tag:    $(GIT_TAG)"; \
	fi

.PHONY: info
info: version ## 显示项目信息
	@echo ""
	@echo "项目信息:"
	@echo "  二进制名称: $(BINARY_NAME)"
	@echo "  构建目录: $(BUILD_DIR)"
	@echo "  Docker 镜像: $(DOCKER_IMAGE):$(DOCKER_TAG)"
	@echo ""
	@echo "Go 环境:"
	@go version
	@echo ""
	@echo "Docker 环境:"
	@docker --version 2>/dev/null || echo "  Docker 未安装"
	@docker-compose --version 2>/dev/null || echo "  docker-compose 未安装"

.PHONY: env-check
env-check: ## 检查开发环境
	@echo "检查开发环境..."
	@echo ""
	@echo "必需工具:"
	@command -v go >/dev/null 2>&1 && echo "  ✓ Go: $(shell go version)" || echo "  ✗ Go: 未安装"
	@command -v docker >/dev/null 2>&1 && echo "  ✓ Docker: $(shell docker --version)" || echo "  ✗ Docker: 未安装"
	@command -v docker-compose >/dev/null 2>&1 && echo "  ✓ docker-compose: $(shell docker-compose --version)" || echo "  ✗ docker-compose: 未安装"
	@echo ""
	@echo "可选工具:"
	@command -v golangci-lint >/dev/null 2>&1 && echo "  ✓ golangci-lint: $(shell golangci-lint --version)" || echo "  ✗ golangci-lint: 未安装 (运行 'make lint' 查看安装说明)"
	@command -v air >/dev/null 2>&1 && echo "  ✓ air: 已安装" || echo "  ✗ air: 未安装 (运行 'go install github.com/cosmtrek/air@latest' 安装)"
	@echo ""
	@echo "Go 模块:"
	@go mod verify && echo "  ✓ 模块验证通过" || echo "  ✗ 模块验证失败"

