# OpsHub 运维管理平台

> 一个现代化的 Kubernetes 集群管理平台，支持多集群管理、RBAC 权限控制、资源监控等功能。

## 功能特性

### 平台功能
- 用户权限管理 (RBAC)
- 部门管理
- 菜单权限控制
- JWT 认证

### Kubernetes 集群管理
- 多集群管理
- 集群资源监控 (节点、Pod、Deployment 等)
- 用户级别的 RBAC 权限隔离
- 用户 KubeConfig 管理
- 集群角色和命名空间角色管理
- 角色绑定管理

### 权限说明
- **平台管理员** (role code == "admin"): 直接使用集群注册的 kubeconfig，拥有完整集群访问权限
- **普通用户**: 需要申请 KubeConfig 并通过角色绑定获取相应的 K8s 权限

## 技术栈

### 后端
- Go 1.21+
- Gin (Web 框架)
- GORM (ORM)
- Cobra + Viper (CLI 和配置管理)
- MySQL 8.0+
- Redis 6.0+
- client-go (Kubernetes Go 客户端)

### 前端
- Vue 3
- TypeScript
- Vite
- Element Plus
- Pinia (状态管理)

## 快速开始

### 方式一：Docker Compose (推荐)

1. 克隆项目
```bash
git clone https://github.com/your-org/opshub.git
cd opshub
```

2. 配置环境变量
```bash
cp .env.example .env
# 编辑 .env 文件，修改数据库、Redis 等配置
```

3. 启动服务
```bash
docker-compose up -d
```

4. 访问应用
- 前端: http://localhost:3000
- 后端 API: http://localhost:9876
- 默认账号: `admin` / `123456`

### 方式二：手动部署

#### 1. 数据库初始化

```bash
# 创建数据库
mysql -u root -p < init_db.sql
```

#### 2. 后端启动

```bash
# 安装依赖
go mod tidy

# 复制配置文件模板
cp config/config.yaml.example config/config.yaml

# 编辑 config/config.yaml 修改数据库和 Redis 配置
vim config/config.yaml

# 运行后端
go run main.go server
```

#### 3. 前端启动

```bash
cd web

# 安装依赖
npm install

# 开发模式
npm run dev

# 生产构建
npm run build
```

## 环境变量

支持通过环境变量覆盖配置文件 (前缀: `OPSHUB_`)

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| `OPSHUB_SERVER_MODE` | 运行模式 (debug/release) | debug |
| `OPSHUB_SERVER_HTTP_PORT` | HTTP 端口 | 9876 |
| `OPSHUB_SERVER_JWT_SECRET` | JWT 密钥 | - |
| `OPSHUB_DATABASE_HOST` | 数据库地址 | 127.0.0.1 |
| `OPSHUB_DATABASE_PORT` | 数据库端口 | 3306 |
| `OPSHUB_DATABASE_DATABASE` | 数据库名称 | opshub |
| `OPSHUB_DATABASE_USERNAME` | 数据库用户名 | root |
| `OPSHUB_DATABASE_PASSWORD` | 数据库密码 | - |
| `OPSHUB_REDIS_HOST` | Redis 地址 | 127.0.0.1 |
| `OPSHUB_REDIS_PORT` | Redis 端口 | 6379 |
| `OPSHUB_REDIS_PASSWORD` | Redis 密码 | - |

## 默认账号

- 用户名: `admin`
- 密码: `123456`

## 项目结构

```
.
├── cmd/                      # 命令行工具
│   ├── root/                # 根命令
│   ├── server/              # 服务启动命令
│   └── version/             # 版本信息命令
├── config/                   # 配置文件
│   └── config.yaml          # 主配置文件
├── internal/                 # 内部代码
│   ├── biz/                 # 业务逻辑层
│   ├── conf/                # 配置管理
│   ├── data/                # 数据层
│   ├── server/              # HTTP 服务器
│   └── service/             # 服务层
├── plugins/                  # 插件系统
│   └── kubernetes/          # Kubernetes 插件
│       ├── biz/             # 业务逻辑
│       ├── data/            # 数据层
│       ├── model/           # 数据模型
│       ├── server/          # HTTP 处理器
│       └── service/         # 服务层
├── pkg/                      # 公共包
│   ├── error/               # 错误处理
│   ├── logger/              # 日志
│   ├── middleware/          # 中间件
│   └── response/            # 响应封装
├── web/                      # 前端代码
│   ├── src/
│   │   ├── api/             # API 请求
│   │   ├── components/      # 公共组件
│   │   ├── router/          # 路由配置
│   │   ├── stores/          # 状态管理
│   │   ├── utils/           # 工具函数
│   │   └── views/           # 页面视图
│   ├── package.json
│   └── vite.config.ts
├── init_db.sql              # 数据库初始化脚本
├── docker-compose.yml       # Docker Compose 配置
├── .env.example             # 环境变量示例
├── Makefile                 # 构建脚本
├── go.mod
└── go.sum
```

## 数据库自动迁移

项目启动时会自动执行以下操作：

1. 创建/更新数据库表结构 (GORM AutoMigrate)
2. 初始化默认数据（如果不存在）:
   - 默认部门
   - 管理员角色 (code: admin)
   - 管理员账号 (admin / 123456)
   - 默认菜单

## 开发指南

### 添加新的 API 接口

1. 在 `internal/service/` 或 `plugins/*/server/` 中添加处理函数
2. 在 `internal/server/` 或 `plugins/*/server/router.go` 中注册路由
3. 在对应的 `biz/` 层实现业务逻辑
4. 在 `data/` 层添加数据访问方法

### 添加新的 Kubernetes 插件功能

1. 在 `plugins/kubernetes/model/` 中定义数据模型
2. 在 `plugins/kubernetes/biz/` 中实现业务逻辑
3. 在 `plugins/kubernetes/service/` 中实现服务层
4. 在 `plugins/kubernetes/server/` 中添加 HTTP 处理器
5. 在 `plugins/kubernetes/server/router.go` 中注册路由

### 前端开发

```bash
cd web

# 开发模式
npm run dev

# 类型检查
npm run type-check

# 代码格式化
npm run lint

# 生产构建
npm run build
```

## 构建

```bash
# 构建后端
make build

# 构建前端
cd web && npm run build

# 使用 Docker 构建
docker build -t opshub:latest .
```

## 命令行工具

```bash
# 查看帮助
./bin/opshub -h

# 启动服务
./bin/opshub server

# 指定配置文件
./bin/opshub server -c config/config.yaml

# 覆盖配置参数
./bin/opshub server -m release -l info

# 使用环境变量
export OPSHUB_SERVER_MODE=release
./bin/opshub server
```

## 常见问题

### 1. 数据库连接失败

检查 `config/config.yaml` 中的数据库配置是否正确，确保 MySQL 服务已启动。

### 2. Redis 连接失败

检查 Redis 服务是否启动，配置是否正确。

### 3. 前端无法访问后端 API

检查后端服务是否启动，端口是否正确，跨域配置是否正确。

### 4. Kubernetes 集群连接失败

确保集群的 kubeconfig 配置正确，集群 API 可访问。

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
