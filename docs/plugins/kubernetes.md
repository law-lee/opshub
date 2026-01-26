# Kubernetes 插件文档

## 概述

Kubernetes 插件是 OpsHub 的核心插件，提供完整的 Kubernetes 集群管理能力。

## 功能特性

### 集群管理
- 多集群接入与管理
- 集群概览与健康检查
- 集群资源监控
- 集群事件查看

### 节点管理
- 节点列表与详情
- 资源监控（CPU、内存、磁盘）
- 污点(Taint)与标签(Label)管理
- 节点驱逐与恢复

### 命名空间管理
- 命名空间创建与删除
- 资源配额设置
- 网络策略配置
- 命名空间隔离管理

### 工作负载管理
- **Deployment**: 无状态应用部署
- **StatefulSet**: 有状态应用部署
- **DaemonSet**: 节点级应用部署
- **Job**: 一次性任务执行
- **CronJob**: 定时任务调度
- 工作负载扩缩容
- 滚动更新与回滚

### 网络管理
- Service 创建与管理
- Ingress 配置与管理
- NetworkPolicy 策略管理
- 网络诊断工具

### 配置管理
- ConfigMap 创建与编辑
- Secret 创建与管理
- 敏感数据加密存储
- 配置版本管理

### 存储管理
- PersistentVolume (PV) 管理
- PersistentVolumeClaim (PVC) 管理
- StorageClass 配置
- 存储资源监控

### 访问控制
- ServiceAccount 管理
- Role 与 RoleBinding 配置
- ClusterRole 与 ClusterRoleBinding 配置
- RBAC 权限审计

### 终端审计
- Web Terminal 远程登录
- 会话录制与回放
- 终端日志完整存储
- 操作审计追溯

### 应用诊断（Arthas）
- Java 应用线程分析
- JVM 运行信息查看
- 方法火焰图生成
- 内存泄漏检测
- 性能瓶颈分析

## 安装与启用

### 通过管理界面安装

1. 登录 OpsHub 系统
2. 进入「系统管理」-「插件管理」
3. 在可用插件列表中找到「Kubernetes」
4. 点击「安装」按钮
5. 刷新页面查看效果

### 通过 API 启用

```bash
# 启用 Kubernetes 插件
curl -X POST http://localhost:9876/api/v1/plugins/kubernetes/enable \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 禁用 Kubernetes 插件
curl -X POST http://localhost:9876/api/v1/plugins/kubernetes/disable \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 使用指南

### 添加 Kubernetes 集群

1. 登录 OpsHub 系统
2. 进入「容器管理」-「集群管理」
3. 点击「添加集群」按钮
4. 输入集群名称、API Server 地址
5. 上传或粘贴 kubeconfig 文件
6. 点击「保存」完成添加

### 查看集群资源

#### 节点管理
- 查看节点列表与详细信息
- 监控节点资源使用情况
- 管理节点标签与污点

#### 工作负载管理
- 查看 Deployment 列表
- 编辑副本数量实现扩缩容
- 查看 Pod 运行状态
- 查看容器日志

#### 存储管理
- 创建 PVC 申请存储资源
- 查看 PV 和 StorageClass
- 监控存储资源使用

### 远程登录终端

1. 进入「容器管理」-「工作负载」
2. 选择目标 Pod
3. 点击「终端」按钮
4. 在 Web 终端中执行命令
5. 所有操作自动录制保存

### 应用诊断

#### 使用 Arthas 诊断 Java 应用

1. 进入「容器管理」-「应用诊断」
2. 选择目标集群和 Pod
3. 点击「诊断」按钮
4. 在诊断界面执行分析命令

常用诊断命令：
```bash
# 查看线程列表
thread

# 生成火焰图
profiler start
# ... 运行一段时间 ...
profiler stop

# 查看 JVM 信息
jad

# 查看方法调用堆栈
trace package.ClassName method
```

## 配置说明

### 权限配置

不同角色对 Kubernetes 资源的访问权限需要通过 RBAC 配置：

1. 进入「权限管理」-「角色管理」
2. 编辑角色，分配 Kubernetes 相关权限
3. 权限包括：查看、创建、编辑、删除等

### 资源配额

在命名空间中设置资源配额限制：

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: my-namespace
spec:
  hard:
    requests.cpu: "10"
    requests.memory: "20Gi"
    limits.cpu: "20"
    limits.memory: "40Gi"
```

## 常见问题

### Q: 如何连接到 Kubernetes 集群？
A: 需要有效的 kubeconfig 文件。可以从集群管理员获取，确保 API Server 地址可访问。

### Q: 如何查看终端操作日志？
A: 所有终端会话自动录制，可以在「审计」-「终端审计」中查看回放。

### Q: 如何对 Java 应用进行诊断？
A: 使用 Arthas 功能，进入「容器管理」-「应用诊断」，选择目标 Pod 即可。

### Q: 为什么某些 Pod 无法访问？
A: 检查网络策略配置，或确保 Pod 所在节点与当前节点的网络连通性。

## 更新日志

### v1.0.0 (2024-01-XX)
- 初始版本发布
- 支持多集群管理
- 完整的工作负载管理
- Web Terminal 终端功能
- Arthas 应用诊断

## 相关文档

- [Kubernetes 官方文档](https://kubernetes.io/docs/)
- [Arthas 用户指南](https://arthas.aliyun.com/)
- [OpsHub 主文档](../../README.md)
