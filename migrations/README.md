# OpsHub 数据库初始化指南

## 概述

本文档介绍如何为 OpsHub 项目初始化数据库。所有必要的表结构和初始化数据都包含在 `migrations/init.sql` 文件中。

## 快速开始

### 1. 创建数据库

首先，使用 MySQL 客户端创建 OpsHub 数据库：

```bash
mysql -u root -p -e "CREATE DATABASE opshub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
```

或者在 MySQL 客户端中执行：

```sql
CREATE DATABASE opshub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 2. 执行初始化脚本

使用 MySQL 导入初始化脚本：

```bash
mysql -u root -p opshub < migrations/init.sql
```

或在 MySQL 客户端中执行：

```sql
SOURCE migrations/init.sql;
```

### 3. 验证初始化

查询是否成功创建了表：

```sql
SHOW TABLES;
```

应该看到约 30 个表。

## 表结构概览

### 系统表 (11 个)

| 表名 | 说明 |
|-----|------|
| `sys_user` | 用户表 |
| `sys_role` | 角色表 |
| `sys_department` | 部门表 |
| `sys_menu` | 菜单表 |
| `sys_position` | 职位表 |
| `sys_user_role` | 用户-角色关联 |
| `sys_role_menu` | 角色-菜单关联 |
| `sys_user_position` | 用户-职位关联 |
| `sys_operation_log` | 操作审计日志 |
| `sys_login_log` | 登录审计日志 |
| `sys_data_log` | 数据变更审计日志 |

### 资产管理表 (5 个)

| 表名 | 说明 |
|-----|------|
| `asset_group` | 资产组 |
| `credentials` | 访问凭证 |
| `hosts` | 主机/服务器 |
| `cloud_accounts` | 云账户 |
| `sys_role_asset_permission` | 角色资产权限 |

### 任务管理表 (3 个)

| 表名 | 说明 |
|-----|------|
| `job_templates` | 任务模板 |
| `job_tasks` | 任务执行记录 |
| `ansible_tasks` | Ansible任务 |

### Kubernetes表 (5 个)

| 表名 | 说明 |
|-----|------|
| `k8s_clusters` | Kubernetes集群 |
| `k8s_user_kube_configs` | 用户kubeconfig |
| `k8s_user_role_bindings` | 用户K8S角色绑定 |
| `k8s_cluster_inspections` | 集群巡检记录 |
| `k8s_terminal_sessions` | 终端会话记录 |

### 监控表 (7 个)

| 表名 | 说明 |
|-----|------|
| `domain_monitors` | 域名监控 |
| `alert_configs` | 告警配置 |
| `alert_channels` | 告警渠道 |
| `alert_receivers` | 告警接收人 |
| `alert_receiver_channels` | 告警接收人-渠道关联 |
| `alert_logs` | 告警日志 |

**总计：31 个表**

## 初始化数据

初始化脚本包含以下基础数据：

### 1. 默认部门
- **总公司** (id=1, code='head') - 顶级部门

### 2. 默认角色
- **管理员** (id=1, code='admin') - 拥有所有权限
- **普通用户** (id=2, code='user') - 基本操作权限

### 3. 默认菜单 (13 个)
包括以下功能模块：
- 仪表盘
- 系统管理（用户、角色、部门、菜单）
- 权限管理
- 资产管理
- 审计日志（操作日志、登录日志）

### 4. 默认用户
- **用户名**: admin
- **密码**: 123456 (bcrypt加密)
- **角色**: 管理员

> ⚠️ **重要**: 生产环境请立即修改默认密码！

## 配置文件

在启动应用之前，确保 `config/config.yaml` 中的数据库配置正确：

```yaml
database:
  driver: mysql
  host: 127.0.0.1
  port: 3306
  database: opshub
  username: root
  password: "your-password"
  max_idle_conns: 10
  max_open_conns: 100
```

## 自动迁移

应用启动时会自动执行 GORM 迁移，确保表结构最新。如果手动修改了表结构，应用可能会自动调整以匹配模型定义。

如果遇到表结构不一致的问题，可以：

1. 查看应用日志中的迁移错误信息
2. 手动执行相应的修改语句
3. 或者重新执行 `init.sql` 脚本（需要先删除表）

## 常见问题

### Q: 如何重置数据库？

```bash
mysql -u root -p -e "DROP DATABASE opshub; CREATE DATABASE opshub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p opshub < migrations/init.sql
```

### Q: 修改了默认密码后忘记了怎么办？

可以直接在数据库中更新用户密码（需要知道正确的加密方式）：

```sql
UPDATE sys_user SET password='新的加密密码' WHERE username='admin';
```

### Q: 如何添加新用户？

```sql
INSERT INTO sys_user (username, password, real_name, email, status, department_id, created_at, updated_at)
VALUES ('newuser', 'encrypted_password', '新用户', 'newuser@example.com', 1, 1, NOW(), NOW());

-- 关联用户到角色
INSERT INTO sys_user_role (user_id, role_id) VALUES (新用户ID, 2);
```

### Q: 数据库字符集问题？

确保使用 `utf8mb4` 字符集以支持 emoji 和其他特殊字符：

```sql
ALTER DATABASE opshub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Q: 外键约束错误？

如果遇到外键约束错误，检查以下几点：

1. 所有父表必须存在
2. 父表主键值必须存在
3. 字符集和排序规则必须一致

可以临时禁用外键检查：

```sql
SET FOREIGN_KEY_CHECKS = 0;
-- 执行操作
SET FOREIGN_KEY_CHECKS = 1;
```

## 索引说明

所有关键字段都已创建索引以优化查询性能：

- **唯一索引**: 用于确保数据唯一性（用户名、角色编码等）
- **普通索引**: 用于加速常见查询（状态、时间戳等）
- **外键索引**: 用于关联表的查询

## 数据类型说明

| 类型 | 用途 | 备注 |
|-----|------|------|
| `bigint unsigned` | 主键和外键 | 支持更大的ID范围 |
| `varchar` | 字符串字段 | 不同长度根据实际需求设定 |
| `text/longtext` | 大文本字段 | JSON数据、长内容等 |
| `json` | JSON数据 | MySQL 5.7+ 支持 |
| `tinyint` | 状态标志 | 0/1 布尔值或枚举状态 |
| `datetime` | 时间戳 | 自动设置创建/更新时间 |

## 备份与恢复

### 备份数据库

```bash
mysqldump -u root -p opshub > opshub_backup.sql
```

### 恢复数据库

```bash
mysql -u root -p opshub < opshub_backup.sql
```

## 性能优化建议

1. **定期清理日志**: 定期删除过期的审计日志以节省空间
2. **添加分区**: 对大表（如 `sys_operation_log`）考虑使用分区
3. **定期优化**: 使用 `OPTIMIZE TABLE` 命令定期优化表

```sql
OPTIMIZE TABLE sys_operation_log;
OPTIMIZE TABLE sys_login_log;
OPTIMIZE TABLE alert_logs;
```

## 相关文档

- [OpsHub 主文档](../README.md)
- [部署指南](../README.md#部署指南)
- [开发指南](../README.md#开发指南)

## 支持

如遇到问题，请：

1. 查看应用日志获取详细错误信息
2. 检查 MySQL 服务是否正常运行
3. 验证数据库连接配置
4. 提交 Issue: [GitHub Issues](https://github.com/ydcloud-dy/opshub/issues)
