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

下面以一个完整的 `test` 插件为例，演示插件开发的全流程。该插件实现一个简单的"测试项"管理功能。

### 5.1 功能设计

- **功能**：测试项的增删改查
- **数据模型**：TestItem（名称、描述、状态）
- **API 接口**：
  - `GET /api/v1/plugins/test/items` - 获取列表
  - `GET /api/v1/plugins/test/items/:id` - 获取详情
  - `POST /api/v1/plugins/test/items` - 创建
  - `PUT /api/v1/plugins/test/items/:id` - 更新
  - `DELETE /api/v1/plugins/test/items/:id` - 删除

### 5.2 后端代码

#### 5.2.1 数据模型

```go
// plugins/test/model/test_item.go
package model

import "time"

type TestItem struct {
    ID          uint      `gorm:"primaryKey" json:"id"`
    Name        string    `gorm:"size:100;not null;index" json:"name"`
    Description string    `gorm:"size:500" json:"description"`
    Status      int       `gorm:"default:1;comment:1-启用 0-禁用" json:"status"`
    CreatedBy   string    `gorm:"size:50" json:"createdBy"`
    CreatedAt   time.Time `json:"createdAt"`
    UpdatedAt   time.Time `json:"updatedAt"`
}

func (TestItem) TableName() string {
    return "test_items"
}

// 请求和响应结构
type CreateTestItemRequest struct {
    Name        string `json:"name" binding:"required,max=100"`
    Description string `json:"description" binding:"max=500"`
    Status      int    `json:"status"`
}

type UpdateTestItemRequest struct {
    Name        string `json:"name" binding:"max=100"`
    Description string `json:"description" binding:"max=500"`
    Status      *int   `json:"status"`
}

type ListTestItemRequest struct {
    Page     int    `form:"page" binding:"min=1"`
    PageSize int    `form:"pageSize" binding:"min=1,max=100"`
    Name     string `form:"name"`
    Status   *int   `form:"status"`
}
```

#### 5.2.2 插件主文件

```go
// plugins/test/plugin.go
package test

import (
    "github.com/gin-gonic/gin"
    "github.com/ydcloud-dy/opshub/internal/plugin"
    "github.com/ydcloud-dy/opshub/plugins/test/model"
    "github.com/ydcloud-dy/opshub/plugins/test/server"
    "gorm.io/gorm"
)

type Plugin struct {
    db *gorm.DB
}

func New() *Plugin {
    return &Plugin{}
}

func (p *Plugin) Name() string {
    return "test"
}

func (p *Plugin) Description() string {
    return "测试插件 - 用于演示插件开发流程"
}

func (p *Plugin) Version() string {
    return "1.0.0"
}

func (p *Plugin) Author() string {
    return "OpsHub Team"
}

func (p *Plugin) Enable(db *gorm.DB) error {
    p.db = db

    // 自动迁移数据库表
    if err := db.AutoMigrate(&model.TestItem{}); err != nil {
        return err
    }

    return nil
}

func (p *Plugin) Disable(db *gorm.DB) error {
    // 禁用时的清理操作（如有后台任务，在此停止）
    return nil
}

func (p *Plugin) RegisterRoutes(router *gin.RouterGroup, db *gorm.DB) {
    server.RegisterRoutes(router, db)
}

func (p *Plugin) GetMenus() []plugin.MenuConfig {
    return []plugin.MenuConfig{
        {
            Name:       "测试中心",
            Path:       "/test",
            Icon:       "Experiment",
            Sort:       200,
            Hidden:     false,
            ParentPath: "",
            Permission: "plugin:test:view",
        },
        {
            Name:       "测试项管理",
            Path:       "/test/items",
            Icon:       "List",
            Sort:       1,
            Hidden:     false,
            ParentPath: "/test",
            Permission: "plugin:test:items:view",
        },
    }
}
```

#### 5.2.3 路由注册

```go
// plugins/test/server/router.go
package server

import (
    "github.com/gin-gonic/gin"
    "gorm.io/gorm"
)

func RegisterRoutes(router *gin.RouterGroup, db *gorm.DB) {
    handler := NewHandler(db)

    // 创建 test 路由组
    testGroup := router.Group("/test")
    {
        // 测试项管理
        items := testGroup.Group("/items")
        {
            items.GET("", handler.ListItems)
            items.GET("/:id", handler.GetItem)
            items.POST("", handler.CreateItem)
            items.PUT("/:id", handler.UpdateItem)
            items.DELETE("/:id", handler.DeleteItem)
        }
    }
}
```

#### 5.2.4 请求处理器

```go
// plugins/test/server/handler.go
package server

import (
    "net/http"
    "strconv"

    "github.com/gin-gonic/gin"
    "github.com/ydcloud-dy/opshub/plugins/test/model"
    "gorm.io/gorm"
)

type Handler struct {
    db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
    return &Handler{db: db}
}

// ListItems 获取测试项列表
func (h *Handler) ListItems(c *gin.Context) {
    var req model.ListTestItemRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": err.Error()})
        return
    }

    // 默认值
    if req.Page == 0 {
        req.Page = 1
    }
    if req.PageSize == 0 {
        req.PageSize = 10
    }

    var items []model.TestItem
    var total int64

    query := h.db.Model(&model.TestItem{})

    // 条件过滤
    if req.Name != "" {
        query = query.Where("name LIKE ?", "%"+req.Name+"%")
    }
    if req.Status != nil {
        query = query.Where("status = ?", *req.Status)
    }

    // 统计总数
    query.Count(&total)

    // 分页查询
    offset := (req.Page - 1) * req.PageSize
    if err := query.Offset(offset).Limit(req.PageSize).Order("id DESC").Find(&items).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "code":    0,
        "message": "success",
        "data": gin.H{
            "list":     items,
            "total":    total,
            "page":     req.Page,
            "pageSize": req.PageSize,
        },
    })
}

// GetItem 获取测试项详情
func (h *Handler) GetItem(c *gin.Context) {
    id, err := strconv.ParseUint(c.Param("id"), 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "无效的 ID"})
        return
    }

    var item model.TestItem
    if err := h.db.First(&item, id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "测试项不存在"})
            return
        }
        c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"code": 0, "message": "success", "data": item})
}

// CreateItem 创建测试项
func (h *Handler) CreateItem(c *gin.Context) {
    var req model.CreateTestItemRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": err.Error()})
        return
    }

    item := model.TestItem{
        Name:        req.Name,
        Description: req.Description,
        Status:      req.Status,
        CreatedBy:   c.GetString("username"), // 从上下文获取当前用户
    }

    if err := h.db.Create(&item).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"code": 0, "message": "创建成功", "data": item})
}

// UpdateItem 更新测试项
func (h *Handler) UpdateItem(c *gin.Context) {
    id, err := strconv.ParseUint(c.Param("id"), 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "无效的 ID"})
        return
    }

    var item model.TestItem
    if err := h.db.First(&item, id).Error; err != nil {
        if err == gorm.ErrRecordNotFound {
            c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "测试项不存在"})
            return
        }
        c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": err.Error()})
        return
    }

    var req model.UpdateTestItemRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": err.Error()})
        return
    }

    // 更新字段
    updates := make(map[string]interface{})
    if req.Name != "" {
        updates["name"] = req.Name
    }
    if req.Description != "" {
        updates["description"] = req.Description
    }
    if req.Status != nil {
        updates["status"] = *req.Status
    }

    if err := h.db.Model(&item).Updates(updates).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"code": 0, "message": "更新成功", "data": item})
}

// DeleteItem 删除测试项
func (h *Handler) DeleteItem(c *gin.Context) {
    id, err := strconv.ParseUint(c.Param("id"), 10, 64)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"code": 400, "message": "无效的 ID"})
        return
    }

    result := h.db.Delete(&model.TestItem{}, id)
    if result.Error != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"code": 500, "message": result.Error.Error()})
        return
    }

    if result.RowsAffected == 0 {
        c.JSON(http.StatusNotFound, gin.H{"code": 404, "message": "测试项不存在"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"code": 0, "message": "删除成功"})
}
```

#### 5.2.5 注册后端插件

在 `internal/server/http.go` 中添加：

```go
import (
    testplugin "github.com/ydcloud-dy/opshub/plugins/test"
)

// 在 NewHTTPServer 函数中注册插件
pluginMgr.Register(testplugin.New())
```

### 5.3 前端代码

#### 5.3.1 API 接口定义

```typescript
// web/src/api/test.ts
import request from '@/utils/request'

// 类型定义
export interface TestItem {
    id: number
    name: string
    description: string
    status: number
    createdBy: string
    createdAt: string
    updatedAt: string
}

export interface ListTestItemParams {
    page?: number
    pageSize?: number
    name?: string
    status?: number
}

export interface CreateTestItemData {
    name: string
    description?: string
    status?: number
}

export interface UpdateTestItemData {
    name?: string
    description?: string
    status?: number
}

// API 函数
export const getTestItemList = (params: ListTestItemParams) => {
    return request.get('/api/v1/plugins/test/items', { params })
}

export const getTestItem = (id: number) => {
    return request.get(`/api/v1/plugins/test/items/${id}`)
}

export const createTestItem = (data: CreateTestItemData) => {
    return request.post('/api/v1/plugins/test/items', data)
}

export const updateTestItem = (id: number, data: UpdateTestItemData) => {
    return request.put(`/api/v1/plugins/test/items/${id}`, data)
}

export const deleteTestItem = (id: number) => {
    return request.delete(`/api/v1/plugins/test/items/${id}`)
}
```

#### 5.3.2 插件入口文件

```typescript
// web/src/plugins/test/index.ts
import { Plugin, PluginMenuConfig, PluginRouteConfig } from '../types'
import { pluginManager } from '../manager'

class TestPlugin implements Plugin {
    name = 'test'
    description = '测试插件 - 用于演示插件开发流程'
    version = '1.0.0'
    author = 'OpsHub Team'

    install(): void {
        console.log(`[Test Plugin] v${this.version} 已安装`)
    }

    uninstall(): void {
        console.log(`[Test Plugin] 已卸载`)
    }

    getMenus(): PluginMenuConfig[] {
        return [
            {
                name: '测试中心',
                path: '/test',
                icon: 'Experiment',
                sort: 200,
                hidden: false,
                parentPath: '',
                permission: 'plugin:test:view'
            },
            {
                name: '测试项管理',
                path: '/test/items',
                icon: 'List',
                sort: 1,
                hidden: false,
                parentPath: '/test',
                permission: 'plugin:test:items:view'
            }
        ]
    }

    getRoutes(): PluginRouteConfig[] {
        return [
            {
                path: '/test',
                name: 'Test',
                component: () => import('@/views/test/Index.vue'),
                meta: {
                    title: '测试中心',
                    icon: 'Experiment'
                },
                children: [
                    {
                        path: 'items',
                        name: 'TestItems',
                        component: () => import('@/views/test/Items.vue'),
                        meta: {
                            title: '测试项管理',
                            icon: 'List',
                            activeMenu: '/test/items'
                        }
                    }
                ]
            }
        ]
    }
}

// 创建实例并注册
const testPlugin = new TestPlugin()
pluginManager.register(testPlugin)

export default testPlugin
```

#### 5.3.3 页面组件 - 容器页面

```vue
<!-- web/src/views/test/Index.vue -->
<template>
    <router-view />
</template>

<script setup lang="ts">
// 容器组件，用于嵌套子路由
</script>
```

#### 5.3.4 页面组件 - 列表页面

```vue
<!-- web/src/views/test/Items.vue -->
<template>
    <div class="test-items-container">
        <!-- 搜索区域 -->
        <el-card class="search-card" shadow="never">
            <el-form :model="searchForm" inline>
                <el-form-item label="名称">
                    <el-input
                        v-model="searchForm.name"
                        placeholder="请输入名称"
                        clearable
                        @keyup.enter="handleSearch"
                    />
                </el-form-item>
                <el-form-item label="状态">
                    <el-select v-model="searchForm.status" placeholder="全部" clearable>
                        <el-option label="启用" :value="1" />
                        <el-option label="禁用" :value="0" />
                    </el-select>
                </el-form-item>
                <el-form-item>
                    <el-button type="primary" @click="handleSearch">搜索</el-button>
                    <el-button @click="handleReset">重置</el-button>
                </el-form-item>
            </el-form>
        </el-card>

        <!-- 操作区域 -->
        <el-card class="table-card" shadow="never">
            <template #header>
                <div class="card-header">
                    <span>测试项列表</span>
                    <el-button type="primary" @click="handleAdd">
                        <el-icon><Plus /></el-icon>
                        新增
                    </el-button>
                </div>
            </template>

            <!-- 表格 -->
            <el-table
                :data="tableData"
                v-loading="loading"
                border
                stripe
            >
                <el-table-column prop="id" label="ID" width="80" />
                <el-table-column prop="name" label="名称" min-width="150" />
                <el-table-column prop="description" label="描述" min-width="200" show-overflow-tooltip />
                <el-table-column prop="status" label="状态" width="100">
                    <template #default="{ row }">
                        <el-tag :type="row.status === 1 ? 'success' : 'danger'">
                            {{ row.status === 1 ? '启用' : '禁用' }}
                        </el-tag>
                    </template>
                </el-table-column>
                <el-table-column prop="createdBy" label="创建人" width="120" />
                <el-table-column prop="createdAt" label="创建时间" width="180" />
                <el-table-column label="操作" width="180" fixed="right">
                    <template #default="{ row }">
                        <el-button type="primary" link @click="handleEdit(row)">编辑</el-button>
                        <el-popconfirm
                            title="确定要删除吗？"
                            @confirm="handleDelete(row.id)"
                        >
                            <template #reference>
                                <el-button type="danger" link>删除</el-button>
                            </template>
                        </el-popconfirm>
                    </template>
                </el-table-column>
            </el-table>

            <!-- 分页 -->
            <el-pagination
                v-model:current-page="pagination.page"
                v-model:page-size="pagination.pageSize"
                :page-sizes="[10, 20, 50, 100]"
                :total="pagination.total"
                layout="total, sizes, prev, pager, next, jumper"
                @size-change="handleSizeChange"
                @current-change="handleCurrentChange"
            />
        </el-card>

        <!-- 新增/编辑对话框 -->
        <el-dialog
            v-model="dialogVisible"
            :title="dialogTitle"
            width="500px"
            @close="handleDialogClose"
        >
            <el-form
                ref="formRef"
                :model="formData"
                :rules="formRules"
                label-width="80px"
            >
                <el-form-item label="名称" prop="name">
                    <el-input v-model="formData.name" placeholder="请输入名称" />
                </el-form-item>
                <el-form-item label="描述" prop="description">
                    <el-input
                        v-model="formData.description"
                        type="textarea"
                        :rows="3"
                        placeholder="请输入描述"
                    />
                </el-form-item>
                <el-form-item label="状态" prop="status">
                    <el-radio-group v-model="formData.status">
                        <el-radio :label="1">启用</el-radio>
                        <el-radio :label="0">禁用</el-radio>
                    </el-radio-group>
                </el-form-item>
            </el-form>
            <template #footer>
                <el-button @click="dialogVisible = false">取消</el-button>
                <el-button type="primary" @click="handleSubmit" :loading="submitLoading">
                    确定
                </el-button>
            </template>
        </el-dialog>
    </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import {
    getTestItemList,
    createTestItem,
    updateTestItem,
    deleteTestItem,
    type TestItem,
    type CreateTestItemData
} from '@/api/test'

// 搜索表单
const searchForm = reactive({
    name: '',
    status: undefined as number | undefined
})

// 分页
const pagination = reactive({
    page: 1,
    pageSize: 10,
    total: 0
})

// 表格数据
const tableData = ref<TestItem[]>([])
const loading = ref(false)

// 对话框
const dialogVisible = ref(false)
const dialogTitle = ref('新增测试项')
const editingId = ref<number | null>(null)
const formRef = ref<FormInstance>()
const submitLoading = ref(false)

// 表单数据
const formData = reactive<CreateTestItemData>({
    name: '',
    description: '',
    status: 1
})

// 表单验证规则
const formRules: FormRules = {
    name: [
        { required: true, message: '请输入名称', trigger: 'blur' },
        { max: 100, message: '名称不能超过100个字符', trigger: 'blur' }
    ],
    description: [
        { max: 500, message: '描述不能超过500个字符', trigger: 'blur' }
    ]
}

// 获取列表数据
const fetchData = async () => {
    loading.value = true
    try {
        const res = await getTestItemList({
            page: pagination.page,
            pageSize: pagination.pageSize,
            name: searchForm.name || undefined,
            status: searchForm.status
        })
        if (res.data.code === 0) {
            tableData.value = res.data.data.list
            pagination.total = res.data.data.total
        }
    } catch (error) {
        console.error('获取数据失败:', error)
    } finally {
        loading.value = false
    }
}

// 搜索
const handleSearch = () => {
    pagination.page = 1
    fetchData()
}

// 重置
const handleReset = () => {
    searchForm.name = ''
    searchForm.status = undefined
    handleSearch()
}

// 分页变化
const handleSizeChange = () => {
    pagination.page = 1
    fetchData()
}

const handleCurrentChange = () => {
    fetchData()
}

// 新增
const handleAdd = () => {
    editingId.value = null
    dialogTitle.value = '新增测试项'
    formData.name = ''
    formData.description = ''
    formData.status = 1
    dialogVisible.value = true
}

// 编辑
const handleEdit = (row: TestItem) => {
    editingId.value = row.id
    dialogTitle.value = '编辑测试项'
    formData.name = row.name
    formData.description = row.description
    formData.status = row.status
    dialogVisible.value = true
}

// 删除
const handleDelete = async (id: number) => {
    try {
        const res = await deleteTestItem(id)
        if (res.data.code === 0) {
            ElMessage.success('删除成功')
            fetchData()
        } else {
            ElMessage.error(res.data.message || '删除失败')
        }
    } catch (error) {
        ElMessage.error('删除失败')
    }
}

// 提交表单
const handleSubmit = async () => {
    if (!formRef.value) return

    await formRef.value.validate(async (valid) => {
        if (!valid) return

        submitLoading.value = true
        try {
            let res
            if (editingId.value) {
                res = await updateTestItem(editingId.value, formData)
            } else {
                res = await createTestItem(formData)
            }

            if (res.data.code === 0) {
                ElMessage.success(editingId.value ? '更新成功' : '创建成功')
                dialogVisible.value = false
                fetchData()
            } else {
                ElMessage.error(res.data.message || '操作失败')
            }
        } catch (error) {
            ElMessage.error('操作失败')
        } finally {
            submitLoading.value = false
        }
    })
}

// 对话框关闭
const handleDialogClose = () => {
    formRef.value?.resetFields()
}

// 初始化
onMounted(() => {
    fetchData()
})
</script>

<style scoped>
.test-items-container {
    padding: 20px;
}

.search-card {
    margin-bottom: 20px;
}

.table-card .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.el-pagination {
    margin-top: 20px;
    justify-content: flex-end;
}
</style>
```

#### 5.3.5 注册前端插件

```typescript
// web/src/main.ts
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
│       ├── model/
│       │   └── test_item.go    # 数据模型
│       └── server/
│           ├── router.go       # 路由注册
│           └── handler.go      # 请求处理器
│
└── web/src/
    ├── api/
    │   └── test.ts             # API 接口
    ├── plugins/
    │   └── test/
    │       └── index.ts        # 插件入口
    └── views/
        └── test/
            ├── Index.vue       # 容器组件
            └── Items.vue       # 列表页面
```

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
