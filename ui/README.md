# ZVPN 管理后台

基于 Vue 3 + TypeScript + Arco Design UI 的 ZVPN 管理后台系统。

## 功能特性

- ✅ 用户认证（JWT）
- ✅ 用户管理（CRUD）
- ✅ 策略管理（CRUD）
- ✅ 路由管理
- ✅ VPN 监控（在线用户、服务器状态）
- ✅ 仪表盘
- ✅ 响应式设计

## 技术栈

- **框架**: Vue 3 + TypeScript
- **构建工具**: Vite
- **UI 库**: Arco Design
- **路由**: Vue Router
- **状态管理**: Pinia
- **HTTP 客户端**: Axios

## 快速开始

### 1. 安装依赖

```bash
npm install
```

### 2. 启动开发服务器

```bash
npm run dev
```

默认地址：http://localhost:3000

### 3. 构建生产版本

```bash
npm run build
```

## 项目结构

```
zvpn-admin/
├── src/
│   ├── api/              # API 接口
│   │   ├── request.ts    # Axios 封装
│   │   ├── auth.ts       # 认证接口
│   │   ├── users.ts      # 用户接口
│   │   ├── policies.ts   # 策略接口
│   │   └── vpn.ts        # VPN 接口
│   ├── views/            # 页面组件
│   │   ├── login/        # 登录页
│   │   ├── dashboard/    # 仪表盘
│   │   ├── users/        # 用户管理
│   │   ├── policies/     # 策略管理
│   │   └── monitor/      # VPN 监控
│   ├── components/       # 公共组件
│   │   └── layout/       # 布局组件
│   ├── stores/           # 状态管理
│   │   └── auth.ts       # 认证状态
│   ├── router/           # 路由配置
│   │   └── index.ts
│   ├── utils/            # 工具函数
│   ├── App.vue           # 根组件
│   └── main.ts           # 入口文件
├── package.json
└── vite.config.ts
```

## API 配置

后端 API 地址配置在 `vite.config.ts` 中：

```typescript
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:8080', // 后端地址
      changeOrigin: true,
    },
  },
}
```

## 默认账号

- 用户名: `admin`
- 密码: `admin123`

## 功能说明

### 1. 仪表盘

- 显示系统关键指标（在线用户、总用户数、策略数等）
- 显示系统信息（VPN 网段、端口、eBPF 状态等）
- 显示在线用户列表

### 2. 用户管理

- 创建/编辑/删除用户
- 设置用户角色（管理员/普通用户）
- 分配策略
- 管理用户状态（激活/禁用）
- 查看用户连接状态和 VPN IP

### 3. 策略管理

- 创建/编辑/删除策略
- 添加/删除路由规则
- 设置带宽限制
- 查看策略详情

### 4. VPN 监控

- 实时显示在线用户列表
- 显示用户 VPN IP
- 显示连接时间
- 自动刷新（30秒）

## 开发说明

### 添加新页面

1. 在 `src/views/` 下创建页面组件
2. 在 `src/router/index.ts` 中添加路由
3. 在布局组件中添加菜单项（如果需要）

### 添加新 API

1. 在 `src/api/` 下创建接口文件
2. 定义 TypeScript 类型
3. 使用 `request` 实例发送请求

### 样式定制

Arco Design 支持主题定制，可以在 `main.ts` 中配置：

```typescript
import { ConfigProvider } from '@arco-design/web-vue'

app.use(ConfigProvider, {
  // 主题配置
})
```

## 部署

### Nginx 配置示例

```nginx
server {
    listen 80;
    server_name admin.zvpn.example.com;
    
    location / {
        root /var/www/zvpn-admin/dist;
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Docker 部署

```dockerfile
FROM node:18-alpine as builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## 浏览器支持

- Chrome >= 87
- Firefox >= 78
- Safari >= 14
- Edge >= 88

## 许可证

MIT License
