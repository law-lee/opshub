# OpsHub 插件开发指南

## 目录

- [一、概述](#一概述)
- [二、插件架构](#二插件架构)
- [三、开发规则](#三开发规则)
- [四、开发流程](#四开发流程)
- [五、Test 插件完整开发示例](#五test-插件完整开发示例)
- [六、一键安装与卸载](#六一键安装与卸载)
- [七、最佳实践](#七最佳实践)

---

## 一、概述

OpsHub 采用插件化架构，允许开发者独立开发、部署和管理功能模块。每个插件包含前端和后端两部分，通过统一的接口与核心系统集成。

### 1.1 插件特点

- **模块化**：各插件独立开发、测试、部署
- **可扩展**：简单的接口支持快速集成新功能
- **解耦合**：核心系统与插件功能清晰分离
- **动态管理**：支持运行时启用/禁用插件
- **状态持久化**：插件启用状态自动保存和恢复

### 1.2 现有插件

| 插件名称 | 标识 | 功能描述 |
|---------|------|---------|
| Kubernetes | kubernetes | 容器集群管理、工作负载、终端审计 |
| Task | task | 任务执行、模板管理、文件分发 |
| Monitor | monitor | 域名监控、告警管理 |

---

## 二、插件架构

### 2.1 目录结构

```
opshub/
├── plugins/                      # 后端插件目录
│   └── [plugin-name]/
│       ├── plugin.go             # 插件主文件，实现 Plugin 接口
│       ├── model/                # 数据库模型
│       │   └── *.go
│       ├── server/               # HTTP 服务层
│       │   ├── router.go         # 路由注册
│       │   └── *_handler.go      # 请求处理器
│       ├── service/              # 业务逻辑层
│       │   └── *.go
│       ├── repository/           # 数据访问层
│       │   └── *.go
│       └── biz/                  # 业务模型
│           └── *.go
│
├── web/src/plugins/              # 前端插件目录
│   ├── manager.ts                # 插件管理器
│   ├── types.ts                  # 类型定义
│   └── [plugin-name]/
│       └── index.ts              # 插件入口文件
│
├── web/src/views/[plugin-name]/  # 前端页面组件
│   └── *.vue
│
├── web/src/api/                  # API 接口文件
│   └── [plugin-name].ts
│
└── internal/plugin/              # 核心插件框架
    └── plugin.go                 # 插件接口定义
```

### 2.2 后端插件接口

```go
// internal/plugin/plugin.go
type Plugin interface {
    // 基本信息
    Name() string        // 插件唯一标识，如 "test"
    Description() string // 插件描述
    Version() string     // 版本号，如 "1.0.0"
    Author() string      // 作者信息

    // 生命周期
    Enable(db *gorm.DB) error   // 启用插件时调用（初始化数据库表、启动后台任务）
    Disable(db *gorm.DB) error  // 禁用插件时调用（清理资源、停止任务）

    // 功能注册
    RegisterRoutes(router *gin.RouterGroup, db *gorm.DB)  // 注册 API 路由
    GetMenus() []MenuConfig                               // 返回菜单配置
}

// 菜单配置
type MenuConfig struct {
    Name       string  // 菜单显示名称
    Path       string  // 前端路由路径
    Icon       string  // 菜单图标
    Sort       int     // 排序号（数字小的优先）
    Hidden     bool    // 是否隐藏
    ParentPath string  // 父菜单路径（空表示一级菜单）
    Permission string  // 权限标识
}
```

### 2.3 前端插件接口

```typescript
// web/src/plugins/types.ts
interface Plugin {
    name: string        // 插件唯一标识
    description: string // 插件描述
    version: string     // 版本号
    author: string      // 作者

    install(): void | Promise<void>      // 安装时调用
    uninstall(): void | Promise<void>    // 卸载时调用

    getMenus?(): PluginMenuConfig[]      // 获取菜单配置
    getRoutes?(): PluginRouteConfig[]    // 获取路由配置
}

interface PluginRouteConfig {
    path: string
    name: string
    component: () => Promise<any>  // 动态导入组件
    meta?: {
        title?: string
        icon?: string
        hidden?: boolean
        permission?: string
        activeMenu?: string
    }
    children?: PluginRouteConfig[]
}
```

---

## 三、开发规则

### 3.1 命名规范

| 类型 | 规范 | 示例 |
|-----|------|------|
| 插件标识 | 小写字母，单词用连字符分隔 | `test`, `domain-monitor` |
| 数据库表名 | 插件前缀 + 下划线 + 功能名 | `test_items`, `test_configs` |
| API 路径 | `/api/v1/plugins/{plugin-name}/{resource}` | `/api/v1/plugins/test/items` |
| 前端路由 | `/{plugin-name}/{page}` | `/test/list` |
| 权限标识 | `plugin:{plugin-name}:{action}` | `plugin:test:view` |

### 3.2 后端开发规则

1. **必须实现 Plugin 接口所有方法**
2. **Enable() 方法中进行数据库迁移**
3. **Disable() 方法中清理后台任务**
4. **路由统一使用 `/api/v1/plugins/{plugin-name}` 前缀**
5. **数据模型必须定义 `TableName()` 方法**
6. **使用统一的响应格式**

响应格式示例：
```go
// 成功响应
response.Success(c, data)

// 错误响应
response.Error(c, http.StatusBadRequest, "错误信息")

// 分页响应
response.SuccessWithPage(c, list, total, page, pageSize)
```

### 3.3 前端开发规则

1. **必须实现 Plugin 接口所有属性和方法**
2. **组件使用动态导入 `() => import(...)`**
3. **API 文件放在 `web/src/api/` 目录**
4. **页面组件放在 `web/src/views/{plugin-name}/` 目录**
5. **在 `main.ts` 中导入插件以自动注册**

### 3.4 路由规则

**后端路由组织：**
```go
// 一级路由组：/api/v1/plugins/{plugin-name}
pluginGroup := router.Group("/{plugin-name}")

// 二级路由组：/api/v1/plugins/{plugin-name}/{resource}
resourceGroup := pluginGroup.Group("/{resource}")
{
    resourceGroup.GET("", handler.List)
    resourceGroup.GET("/:id", handler.Get)
    resourceGroup.POST("", handler.Create)
    resourceGroup.PUT("/:id", handler.Update)
    resourceGroup.DELETE("/:id", handler.Delete)
}
```

**前端路由组织：**
```typescript
{
    path: '/{plugin-name}',
    name: 'PluginName',
    component: () => import('@/views/{plugin-name}/Index.vue'),
    children: [
        {
            path: 'list',
            name: 'PluginList',
            component: () => import('@/views/{plugin-name}/List.vue')
        }
    ]
}
```

---

## 四、开发流程

### 4.1 整体流程图

```
┌──────────────────────────────────────────────────────────────────┐
│                        插件开发流程                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 规划设计                                                      │
│     ├── 确定插件名称和功能                                         │
│     ├── 设计数据模型                                              │
│     └── 规划 API 接口                                             │
│                                                                  │
│  2. 后端开发                                                      │
│     ├── 创建插件目录结构                                           │
│     ├── 定义数据模型 (model/)                                     │
│     ├── 实现 Plugin 接口 (plugin.go)                              │
│     ├── 编写处理器 (server/)                                      │
│     └── 注册插件                                                  │
│                                                                  │
│  3. 前端开发                                                      │
│     ├── 创建插件入口 (plugins/{name}/index.ts)                    │
│     ├── 定义 API 接口 (api/{name}.ts)                            │
│     ├── 开发页面组件 (views/{name}/)                              │
│     └── 注册插件                                                  │
│                                                                  │
│  4. 测试验证                                                      │
│     ├── 启动后端服务                                              │
│     ├── 启动前端服务                                              │
│     └── 测试功能完整性                                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 4.2 详细步骤

#### 步骤 1：创建后端插件目录

```bash
mkdir -p plugins/{plugin-name}/{model,server,service,repository,biz}
touch plugins/{plugin-name}/plugin.go
touch plugins/{plugin-name}/go.mod  # 如果需要独立依赖
```

#### 步骤 2：定义数据模型

```go
// plugins/{plugin-name}/model/item.go
package model

import "time"

type Item struct {
    ID          uint      `gorm:"primaryKey" json:"id"`
    Name        string    `gorm:"size:100;not null" json:"name"`
    Description string    `gorm:"size:500" json:"description"`
    Status      int       `gorm:"default:1;index" json:"status"`
    CreatedBy   string    `gorm:"size:50" json:"createdBy"`
    CreatedAt   time.Time `json:"createdAt"`
    UpdatedAt   time.Time `json:"updatedAt"`
}

func (Item) TableName() string {
    return "plugin_name_items"
}
```

#### 步骤 3：实现 Plugin 接口

```go
// plugins/{plugin-name}/plugin.go
package pluginname

import (
    "github.com/gin-gonic/gin"
    "github.com/ydcloud-dy/opshub/internal/plugin"
    "github.com/ydcloud-dy/opshub/plugins/{plugin-name}/model"
    "github.com/ydcloud-dy/opshub/plugins/{plugin-name}/server"
    "gorm.io/gorm"
)

type Plugin struct {
    db *gorm.DB
}

func New() *Plugin {
    return &Plugin{}
}

func (p *Plugin) Name() string        { return "{plugin-name}" }
func (p *Plugin) Description() string { return "插件描述" }
func (p *Plugin) Version() string     { return "1.0.0" }
func (p *Plugin) Author() string      { return "Your Name" }

func (p *Plugin) Enable(db *gorm.DB) error {
    p.db = db
    // 自动迁移数据库表
    return db.AutoMigrate(&model.Item{})
}

func (p *Plugin) Disable(db *gorm.DB) error {
    // 清理资源（如停止后台任务）
    return nil
}

func (p *Plugin) RegisterRoutes(router *gin.RouterGroup, db *gorm.DB) {
    server.RegisterRoutes(router, db)
}

func (p *Plugin) GetMenus() []plugin.MenuConfig {
    return []plugin.MenuConfig{
        {
            Name:       "插件名称",
            Path:       "/{plugin-name}",
            Icon:       "Setting",
            Sort:       100,
            Hidden:     false,
            ParentPath: "",
            Permission: "plugin:{plugin-name}:view",
        },
    }
}
```

#### 步骤 4：注册后端插件

```go
// internal/server/http.go
import (
    pluginname "github.com/ydcloud-dy/opshub/plugins/{plugin-name}"
)

func NewHTTPServer(...) {
    // ... 其他代码

    // 注册插件
    pluginMgr.Register(pluginname.New())

    // ... 其他代码
}
```

#### 步骤 5：创建前端插件

```typescript
// web/src/plugins/{plugin-name}/index.ts
import { Plugin, PluginMenuConfig, PluginRouteConfig } from '../types'
import { pluginManager } from '../manager'

class PluginNamePlugin implements Plugin {
    name = '{plugin-name}'
    description = '插件描述'
    version = '1.0.0'
    author = 'Your Name'

    install(): void {
        console.log(`${this.name} 插件已安装`)
    }

    uninstall(): void {
        console.log(`${this.name} 插件已卸载`)
    }

    getMenus(): PluginMenuConfig[] {
        return [
            {
                name: '插件名称',
                path: '/{plugin-name}',
                icon: 'Setting',
                sort: 100,
                hidden: false,
                parentPath: '',
                permission: 'plugin:{plugin-name}:view'
            }
        ]
    }

    getRoutes(): PluginRouteConfig[] {
        return [
            {
                path: '/{plugin-name}',
                name: 'PluginName',
                component: () => import('@/views/{plugin-name}/Index.vue'),
                meta: { title: '插件名称' }
            }
        ]
    }
}

const plugin = new PluginNamePlugin()
pluginManager.register(plugin)
export default plugin
```

#### 步骤 6：注册前端插件

```typescript
// web/src/main.ts
import '@/plugins/{plugin-name}'
```

---

## 五、Test 插件完整开发示例

下面以实际的 `test` 插件为例，演示一个简单的插件开发流程。该插件展示插件安装成功后的欢迎页面。

### 5.1 功能设计

- **功能**：显示插件信息和测试交互功能
- **后端 API**：
  - `GET /api/v1/plugins/test/hello` - 测试接口
  - `GET /api/v1/plugins/test/info` - 获取插件信息
- **前端页面**：插件欢迎页面（展示插件信息、测试功能）

### 5.2 后端代码

#### 5.2.1 插件主文件

```go
// plugins/test/plugin.go
package test

import (
	"github.com/gin-gonic/gin"
	"github.com/ydcloud-dy/opshub/internal/plugin"
	"gorm.io/gorm"
)

// TestPlugin 测试插件
type TestPlugin struct{}

// New 创建测试插件实例
func New() plugin.Plugin {
	return &TestPlugin{}
}

// Name 插件名称
func (p *TestPlugin) Name() string {
	return "test"
}

// Description 插件描述
func (p *TestPlugin) Description() string {
	return "这是一个简单的测试插件，用于测试插件安装功能"
}

// Version 插件版本
func (p *TestPlugin) Version() string {
	return "1.0.0"
}

// Author 插件作者
func (p *TestPlugin) Author() string {
	return "J"
}

// Enable 启用插件
func (p *TestPlugin) Enable(db *gorm.DB) error {
	// 可以在这里初始化数据库表、配置等
	// 例如：db.AutoMigrate(&TestModel{})
	return nil
}

// Disable 禁用插件
func (p *TestPlugin) Disable(db *gorm.DB) error {
	// 清理资源
	return nil
}

// RegisterRoutes 注册路由
func (p *TestPlugin) RegisterRoutes(router *gin.RouterGroup, db *gorm.DB) {
	// 创建测试路由组
	testGroup := router.Group("/test")
	{
		// 测试接口
		testGroup.GET("/hello", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"code":    0,
				"message": "Hello from Test Plugin!",
				"data": gin.H{
					"plugin":  "test",
					"version": "1.0.0",
					"status":  "running",
				},
			})
		})

		// 获取插件信息
		testGroup.GET("/info", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"code":    0,
				"message": "success",
				"data": gin.H{
					"name":        p.Name(),
					"description": p.Description(),
					"version":     p.Version(),
					"author":      p.Author(),
				},
			})
		})
	}
}

// GetMenus 获取菜单配置
func (p *TestPlugin) GetMenus() []plugin.MenuConfig {
	return []plugin.MenuConfig{
		{
			Name:       "测试插件",
			Path:       "/test",
			Icon:       "Grape",
			Sort:       95,
			Hidden:     false,
			ParentPath: "",
		},
		{
			Name:       "测试首页",
			Path:       "/test/home",
			Icon:       "House",
			Sort:       1,
			Hidden:     false,
			ParentPath: "/test",
		},
	}
}
```

#### 5.2.2 注册后端插件

在 `internal/server/http.go` 中添加：

```go
import (
	testplugin "github.com/ydcloud-dy/opshub/plugins/test"
)

// 在 NewHTTPServer 函数中注册插件
pluginMgr.Register(testplugin.New())
```

### 5.3 前端代码

#### 5.3.1 插件入口文件

```typescript
// web/src/plugins/test/index.ts
import type { Plugin, PluginMenuConfig, PluginRouteConfig } from '../types'
import { pluginManager } from '../manager'
import TestHome from './components/TestHome.vue'

/**
 * 测试插件
 */
class TestPlugin implements Plugin {
  name = 'test'
  description = '这是一个简单的测试插件，用于测试插件安装功能'
  version = '1.0.0'
  author = 'J'

  async install() {
    console.log('[Test Plugin] 插件安装中...')
  }

  async uninstall() {
    console.log('[Test Plugin] 插件卸载中...')
  }

  getMenus(): PluginMenuConfig[] {
    return [
      {
        name: '测试插件',
        path: '/test',
        icon: 'Grape',
        sort: 95,
        hidden: false,
        parentPath: '',
      },
      {
        name: '测试首页',
        path: '/test/home',
        icon: 'House',
        sort: 1,
        hidden: false,
        parentPath: '/test',
      }
    ]
  }

  getRoutes(): PluginRouteConfig[] {
    return [
      {
        path: '/test/home',
        name: 'TestHome',
        component: TestHome,
        meta: { title: '测试首页' }
      }
    ]
  }
}

// 创建插件实例并注册
const testPlugin = new TestPlugin()
pluginManager.register(testPlugin)

export default testPlugin
```

#### 5.3.2 页面组件 - TestHome.vue

```vue
<template>
  <div class="test-home-container">
    <el-card class="welcome-card">
      <template #header>
        <div class="card-header">
          <el-icon class="header-icon" color="#409eff"><Grape /></el-icon>
          <span class="header-title">测试插件</span>
        </div>
      </template>

      <div class="content">
        <h1>🎉 测试插件安装成功！</h1>
        <p class="subtitle">恭喜你，插件系统运行正常</p>

        <el-divider />

        <div class="info-section">
          <h3>插件信息</h3>
          <el-descriptions :column="2" border>
            <el-descriptions-item label="插件名称">测试插件</el-descriptions-item>
            <el-descriptions-item label="插件版本">1.0.0</el-descriptions-item>
            <el-descriptions-item label="插件作者">J</el-descriptions-item>
            <el-descriptions-item label="安装时间">{{ currentTime }}</el-descriptions-item>
          </el-descriptions>
        </div>

        <el-divider />

        <div class="action-section">
          <h3>测试功能</h3>
          <el-space wrap>
            <el-button type="primary" @click="showMessage">显示消息</el-button>
            <el-button type="success" @click="counter++">计数器: {{ counter }}</el-button>
            <el-button type="warning" @click="toggleColor">切换颜色</el-button>
          </el-space>

          <div v-if="showColorBlock" class="color-block" :style="{ background: currentColor }">
            当前颜色: {{ currentColor }}
          </div>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Grape } from '@element-plus/icons-vue'

const currentTime = ref(new Date().toLocaleString('zh-CN'))
const counter = ref(0)
const showColorBlock = ref(false)
const currentColor = ref('#409eff')

const colors = ['#409eff', '#67c23a', '#e6a23c', '#f56c6c', '#909399']
let colorIndex = 0

const showMessage = () => {
  ElMessage.success('测试插件功能正常！')
}

const toggleColor = () => {
  showColorBlock.value = true
  colorIndex = (colorIndex + 1) % colors.length
  currentColor.value = colors[colorIndex]
}
</script>

<style scoped lang="scss">
.test-home-container {
  padding: 24px;

  .welcome-card {
    max-width: 800px;
    margin: 0 auto;

    .card-header {
      display: flex;
      align-items: center;
      gap: 12px;

      .header-icon {
        font-size: 28px;
      }

      .header-title {
        font-size: 20px;
        font-weight: 600;
      }
    }
  }

  .content {
    text-align: center;

    h1 {
      color: #303133;
      margin-bottom: 12px;
    }

    .subtitle {
      color: #606266;
      font-size: 16px;
      margin-bottom: 24px;
    }

    .info-section,
    .action-section {
      margin: 24px 0;

      h3 {
        margin-bottom: 16px;
        color: #303133;
      }
    }

    .color-block {
      margin-top: 20px;
      padding: 40px;
      border-radius: 8px;
      color: white;
      font-size: 18px;
      font-weight: 600;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
      animation: fadeIn 0.3s;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
        transform: scale(0.9);
      }
      to {
        opacity: 1;
        transform: scale(1);
      }
    }
  }
}
</style>
```

#### 5.3.3 注册前端插件

在 `web/src/main.ts` 中添加：

```typescript
// 在其他插件导入后添加
import '@/plugins/test'
```

### 5.4 目录结构总览

完成后的目录结构：

```
opshub/
├── plugins/
│   └── test/
│       ├── plugin.go           # 插件主文件
│       └── server/
│           └── router.go       # 路由注册（可选）
│
└── web/src/
    ├── plugins/
    │   └── test/
    │       ├── index.ts        # 插件入口
    │       └── components/
    │           └── TestHome.vue # 首页组件
    └── views/
        └── test/
            └── Index.vue       # 容器组件
```

### 5.5 测试插件

1. **后端测试**：调用 API 接口
   ```bash
   curl http://localhost:9876/api/v1/plugins/test/hello
   curl http://localhost:9876/api/v1/plugins/test/info
   ```

2. **前端测试**：访问菜单
   - 登录系统
   - 在左侧菜单看到"测试插件"菜单
   - 点击"测试首页"进入插件页面
   - 测试页面上的各个功能按钮

### 5.5 一键安装后的手动配置

虽然系统支持一键安装/卸载，但新插件需要手动配置代码才能完全集成。以下是详细步骤：

#### 5.5.1 后端配置

**第1步**：在 `internal/server/http.go` 中导入并注册插件

找到 `NewHTTPServer()` 函数，在现有插件注册代码后添加：

```go
import (
	// ... 其他导入
	testplugin "github.com/ydcloud-dy/opshub/plugins/test"
)

func NewHTTPServer(...) {
	// ... 其他代码

	// 注册所有内置插件
	pluginMgr.Register(kubernetes.New())     // 已存在
	pluginMgr.Register(task.New())           // 已存在
	pluginMgr.Register(monitor.New())        // 已存在
	pluginMgr.Register(testplugin.New())     // 新增：测试插件

	// ... 其他代码
}
```

**第2步**：重启后端服务

```bash
go run main.go server
```

此时后端 API 应该可以访问：
```bash
curl http://localhost:9876/api/v1/plugins/test/hello
```

#### 5.5.2 前端配置

**第1步**：在 `web/src/main.ts` 中导入插件

找到已有的插件导入，添加新插件：

```typescript
// web/src/main.ts
// ... 其他代码

// 导入插件
import '@/plugins/kubernetes'  // 已存在
import '@/plugins/task'        // 已存在
import '@/plugins/monitor'     // 已存在
import '@/plugins/test'        // 新增：测试插件

// ... 其他代码
```

**第2步**：重启前端开发服务

```bash
cd web
npm run dev
```

此时可以：
- 看到左侧菜单中出现"测试插件"菜单
- 点击菜单进入插件页面
- 使用插件的所有功能

#### 5.5.3 验证配置

| 配置项 | 检查方式 | 预期结果 |
|-------|---------|---------|
| 后端 API | `curl /api/v1/plugins/test/hello` | 返回 200 和 JSON 数据 |
| 后端路由 | `curl /api/v1/plugins/test/info` | 返回 200 和插件信息 |
| 前端菜单 | 登录系统，查看左侧菜单 | 显示"测试插件"菜单 |
| 前端路由 | 点击菜单项 | 正常跳转到插件页面 |
| 插件状态 | 访问插件管理页面 | 插件显示为"已启用" |

### 5.6 关键要点总结

| 要点 | 说明 |
|-----|------|
| 后端入口 | `plugins/test/plugin.go` - 必须实现 Plugin 接口 |
| 后端注册 | `internal/server/http.go` 中导入并调用 `pluginMgr.Register()` |
| 前端入口 | `web/src/plugins/test/index.ts` - 注册插件和菜单 |
| 前端注册 | `web/src/main.ts` 中导入插件：`import '@/plugins/test'` |
| 路由注册 | `RegisterRoutes()` - 在此方法中注册 API 路由 |
| 菜单配置 | `GetMenus()` - 返回菜单配置数组 |
| 前端路由 | `getRoutes()` - 返回动态路由配置 |
| 组件导入 | 使用 dynamic import：`() => import('@/views/test/Index.vue')` |
| 热更新 | 后端：重启 Go 服务；前端：自动热更新（npm run dev）|
| 一键安装 | 通过管理界面安装，但需要手动添加代码才能在应用启动时加载 |


---

## 六、一键安装与卸载

### 6.1 后端安装流程

```
┌─────────────────────────────────────────────────────────────┐
│                     后端插件安装流程                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 服务启动                                                 │
│     │                                                       │
│     ▼                                                       │
│  2. 创建 PluginManager                                      │
│     │                                                       │
│     ▼                                                       │
│  3. 注册插件 (pluginMgr.Register)                           │
│     │  - 检查插件状态记录是否存在                             │
│     │  - 不存在则创建（默认禁用）                             │
│     │                                                       │
│     ▼                                                       │
│  4. 启用插件 (pluginMgr.Enable)                             │
│     │  - 调用 plugin.Enable(db)                             │
│     │  - 执行数据库迁移                                      │
│     │  - 启动后台任务（如有）                                 │
│     │  - 更新数据库状态为启用                                 │
│     │                                                       │
│     ▼                                                       │
│  5. 注册路由 (pluginMgr.RegisterAllRoutes)                  │
│     │  - 只为已启用的插件注册路由                             │
│     │  - 调用 plugin.RegisterRoutes(router, db)             │
│     │                                                       │
│     ▼                                                       │
│  6. 服务就绪，插件可用                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 后端卸载流程

```
┌─────────────────────────────────────────────────────────────┐
│                     后端插件卸载流程                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 调用 pluginMgr.Disable(pluginName)                     │
│     │                                                       │
│     ▼                                                       │
│  2. 调用 plugin.Disable(db)                                │
│     │  - 停止后台任务                                        │
│     │  - 清理临时资源                                        │
│     │  - 注意：通常不删除数据表                               │
│     │                                                       │
│     ▼                                                       │
│  3. 更新数据库状态为禁用                                      │
│     │                                                       │
│     ▼                                                       │
│  4. 下次启动时不会注册该插件的路由                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 前端安装流程

```
┌─────────────────────────────────────────────────────────────┐
│                     前端插件安装流程                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 页面加载 (main.ts)                                      │
│     │                                                       │
│     ▼                                                       │
│  2. 导入插件模块                                             │
│     │  import '@/plugins/test'                              │
│     │  - 执行插件文件                                        │
│     │  - 调用 pluginManager.register(plugin)                │
│     │                                                       │
│     ▼                                                       │
│  3. 批量安装插件                                             │
│     │  for (plugin of pluginManager.getAll()) {             │
│     │      pluginManager.install(plugin.name)               │
│     │  }                                                    │
│     │                                                       │
│     ▼                                                       │
│  4. install() 方法执行                                      │
│     │  - 调用 plugin.install()                              │
│     │  - 获取路由配置 plugin.getRoutes()                     │
│     │  - 动态添加路由 router.addRoute('Layout', route)       │
│     │  - 保存状态到 localStorage                             │
│     │                                                       │
│     ▼                                                       │
│  5. 插件就绪，菜单和路由可用                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.4 前端卸载流程

```
┌─────────────────────────────────────────────────────────────┐
│                     前端插件卸载流程                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. 调用 pluginManager.uninstall(pluginName)               │
│     │                                                       │
│     ▼                                                       │
│  2. 执行 plugin.uninstall()                                │
│     │  - 清理全局注册的组件                                  │
│     │  - 清理事件监听器                                      │
│     │                                                       │
│     ▼                                                       │
│  3. 从 localStorage 删除记录                                 │
│     │                                                       │
│     ▼                                                       │
│  4. 标记为已卸载                                             │
│     │                                                       │
│     ▼                                                       │
│  5. 提示用户刷新页面                                         │
│     │  （Vue Router 不支持运行时移除路由）                    │
│     │                                                       │
│     ▼                                                       │
│  6. 刷新后路由不再注册                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.5 管理 API 接口

后端提供了插件管理的 API 接口：

| 方法 | 路径 | 说明 |
|-----|------|------|
| GET | `/api/v1/plugins` | 获取所有插件列表 |
| GET | `/api/v1/plugins/:name` | 获取插件详情 |
| POST | `/api/v1/plugins/:name/enable` | 启用插件 |
| POST | `/api/v1/plugins/:name/disable` | 禁用插件 |
| GET | `/api/v1/plugins/:name/menus` | 获取插件菜单配置 |

### 6.6 快速安装脚本

可以创建一个脚本来自动化插件的安装：

```bash
#!/bin/bash
# scripts/install-plugin.sh

PLUGIN_NAME=$1

if [ -z "$PLUGIN_NAME" ]; then
    echo "用法: ./install-plugin.sh <plugin-name>"
    exit 1
fi

echo "开始安装插件: $PLUGIN_NAME"

# 1. 创建后端目录结构
mkdir -p plugins/$PLUGIN_NAME/{model,server,service,repository,biz}

# 2. 创建基础文件
cat > plugins/$PLUGIN_NAME/plugin.go << 'EOF'
package ${PLUGIN_NAME}

import (
    "github.com/gin-gonic/gin"
    "github.com/ydcloud-dy/opshub/internal/plugin"
    "gorm.io/gorm"
)

type Plugin struct {
    db *gorm.DB
}

func New() *Plugin {
    return &Plugin{}
}

func (p *Plugin) Name() string        { return "${PLUGIN_NAME}" }
func (p *Plugin) Description() string { return "${PLUGIN_NAME} 插件" }
func (p *Plugin) Version() string     { return "1.0.0" }
func (p *Plugin) Author() string      { return "OpsHub Team" }

func (p *Plugin) Enable(db *gorm.DB) error {
    p.db = db
    return nil
}

func (p *Plugin) Disable(db *gorm.DB) error {
    return nil
}

func (p *Plugin) RegisterRoutes(router *gin.RouterGroup, db *gorm.DB) {
    // TODO: 注册路由
}

func (p *Plugin) GetMenus() []plugin.MenuConfig {
    return []plugin.MenuConfig{}
}
EOF

# 替换占位符
sed -i '' "s/\${PLUGIN_NAME}/$PLUGIN_NAME/g" plugins/$PLUGIN_NAME/plugin.go

# 3. 创建前端目录
mkdir -p web/src/plugins/$PLUGIN_NAME
mkdir -p web/src/views/$PLUGIN_NAME

# 4. 创建前端插件入口
cat > web/src/plugins/$PLUGIN_NAME/index.ts << EOF
import { Plugin, PluginMenuConfig, PluginRouteConfig } from '../types'
import { pluginManager } from '../manager'

class ${PLUGIN_NAME^}Plugin implements Plugin {
    name = '$PLUGIN_NAME'
    description = '$PLUGIN_NAME 插件'
    version = '1.0.0'
    author = 'OpsHub Team'

    install(): void {
        console.log(\`[\${this.name}] 插件已安装\`)
    }

    uninstall(): void {
        console.log(\`[\${this.name}] 插件已卸载\`)
    }

    getMenus(): PluginMenuConfig[] {
        return []
    }

    getRoutes(): PluginRouteConfig[] {
        return []
    }
}

const plugin = new ${PLUGIN_NAME^}Plugin()
pluginManager.register(plugin)
export default plugin
EOF

echo "插件 $PLUGIN_NAME 基础结构已创建"
echo ""
echo "后续步骤:"
echo "1. 编辑 plugins/$PLUGIN_NAME/model/ 添加数据模型"
echo "2. 编辑 plugins/$PLUGIN_NAME/server/ 添加路由和处理器"
echo "3. 在 internal/server/http.go 中注册插件"
echo "4. 编辑前端文件添加页面和路由"
echo "5. 在 web/src/main.ts 中导入插件"
```

---

## 七、最佳实践

### 7.1 代码组织

1. **保持插件独立性**：插件之间尽量不要相互依赖
2. **使用清晰的命名**：文件名、函数名、变量名要能准确表达用途
3. **分层架构**：handler → service → repository 清晰分层
4. **统一错误处理**：使用统一的错误响应格式

### 7.2 数据库设计

1. **表名前缀**：使用插件名作为表名前缀，如 `test_items`
2. **软删除**：考虑使用软删除而非物理删除
3. **索引优化**：为常用查询字段添加索引
4. **数据迁移**：在 `Enable()` 中使用 `AutoMigrate`

### 7.3 API 设计

1. **RESTful 风格**：遵循 RESTful API 设计规范
2. **版本控制**：API 路径包含版本号 `/api/v1/`
3. **统一响应**：使用统一的响应格式 `{code, message, data}`
4. **参数验证**：使用 `binding` tag 进行参数验证

### 7.4 前端开发

1. **组件复用**：提取可复用的组件
2. **类型安全**：使用 TypeScript 定义接口类型
3. **错误处理**：统一处理 API 错误
4. **状态管理**：复杂场景使用 Pinia 管理状态

### 7.5 安全考虑

1. **权限控制**：为每个菜单和 API 配置权限标识
2. **输入验证**：验证所有用户输入
3. **SQL 注入**：使用 GORM 的参数化查询
4. **XSS 防护**：前端渲染时注意转义

---

## 附录

### A. 常用命令

```bash
# 启动后端服务
go run cmd/main.go

# 启动前端开发服务
cd web && npm run dev

# 构建前端
cd web && npm run build

# 运行测试
go test ./plugins/test/...
```

### B. 常见问题

**Q: 插件路由没有生效？**
A: 检查是否在 `internal/server/http.go` 中注册了插件，以及插件是否已启用。

**Q: 前端菜单没有显示？**
A: 检查 `main.ts` 是否导入了插件，以及 `getMenus()` 返回值是否正确。

**Q: 数据库表没有创建？**
A: 检查 `Enable()` 方法中的 `AutoMigrate` 是否正确执行。

### C. 参考资源

- [Gin 框架文档](https://gin-gonic.com/docs/)
- [GORM 文档](https://gorm.io/docs/)
- [Vue 3 文档](https://vuejs.org/)
- [Element Plus 文档](https://element-plus.org/)
