# OpsHub 开源数据库梳理总结

## 文件清单

为了方便开源后的快速部署，已生成以下文件：

### 1. **migrations/init.sql** (33 KB, 698 行)
完整的数据库初始化脚本，包含：
- 所有 33 个表的创建语句
- 完整的字段定义和注释
- 所有外键约束和索引
- 初始化数据（默认部门、角色、菜单、用户）

**使用方式**:
```bash
mysql -u root -p opshub < migrations/init.sql
```

### 2. **migrations/README.md** (6.4 KB)
数据库初始化指南，包含：
- 快速开始步骤
- 表结构概览
- 初始化数据说明
- 常见问题解答
- 备份与恢复方法
- 性能优化建议

### 3. **migrations/DATABASE.md** (11 KB)
详细的数据库参考文档，包含：
- 完整的表统计
- 数据模型关系图
- 字段类型对照表
- 性能优化策略
- 常见SQL查询示例
- 故障排查方法

## 数据库架构

### 表统计 (33 个表)

```
RBAC系统       → 11个表 (sys_user, sys_role, sys_department 等)
审计日志       → 3个表  (sys_operation_log, sys_login_log 等)
资产管理       → 5个表  (asset_group, hosts, credentials 等)
任务管理       → 3个表  (job_templates, job_tasks 等)
Kubernetes    → 5个表  (k8s_clusters, k8s_user_kube_configs 等)
监控告警       → 6个表  (domain_monitors, alert_configs 等)
```

### 初始化数据

| 类型 | 数量 | 说明 |
|-----|------|------|
| 部门 | 1 | 总公司 |
| 角色 | 2 | 管理员、普通用户 |
| 菜单 | 16 | 系统各功能菜单 |
| 用户 | 1 | admin (密码: 123456) |

## 快速开始步骤

### 步骤 1: 创建数据库
```bash
mysql -u root -p -e "CREATE DATABASE opshub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
```

### 步骤 2: 导入初始化脚本
```bash
mysql -u root -p opshub < migrations/init.sql
```

### 步骤 3: 配置应用
编辑 `config/config.yaml`:
```yaml
database:
  driver: mysql
  host: 127.0.0.1
  port: 3306
  database: opshub
  username: root
  password: "your-password"
```

### 步骤 4: 启动应用
```bash
go run main.go server
```

## 关键特性

### 1. RBAC 权限管理
- 用户、角色、部门三级体系
- 菜单级权限控制
- 资产级权限控制
- 职位管理支持

### 2. 完整审计追溯
- 操作审计日志（谁做了什么）
- 登录审计日志（登录历史）
- 数据变更日志（修改前后对比）

### 3. 资产管理
- 主机/服务器管理
- 云账户集成（阿里云、腾讯云等）
- 按组织分组管理
- 灵活的权限分配

### 4. 任务编排
- 脚本模板管理
- 任务执行与历史
- Ansible 集成
- 支持多种脚本语言

### 5. Kubernetes 多集群管理
- 多集群接入
- 用户权限绑定
- 集群巡检报告
- 终端会话录制

### 6. 监控告警
- 域名监控（SSL证书过期提醒）
- 灵活的告警规则
- 多渠道通知（邮件、钉钉、企业微信等）
- 完整的告警日志

## 扩展性设计

### 插件系统
所有高级功能都以插件形式提供：

```
plugins/
├── kubernetes/     # Kubernetes 管理插件
├── task/          # 任务管理插件
└── monitor/       # 监控告警插件
```

可以轻松开发新插件而无需修改核心代码。

### 表设计规范

1. **软删除**: 所有表都支持 soft delete，确保数据可追溯
2. **时间戳**: 所有表都有 created_at 和 updated_at
3. **自增ID**: 使用 bigint unsigned 支持大量数据
4. **字符集**: 统一使用 utf8mb4，支持 emoji
5. **索引**: 对所有关键字段建立索引，优化查询性能

## 开源建议

### 1. 修改默认密码
**生产部署前，必须修改默认 admin 用户密码**

```sql
-- 使用应用的密码加密方式更新密码
UPDATE sys_user SET password='new_encrypted_password' WHERE username='admin';
```

### 2. 修改敏感数据
- JWT 密钥
- 数据库密钥（用于加密敏感字段）
- API 密钥

### 3. 添加注释和文档
已在所有表和字段上添加了详细的中文注释。

### 4. 性能优化建议
- 定期清理旧日志
- 对大表使用分区
- 定期优化表空间
- 监控慢查询

## 文件大小统计

| 文件 | 大小 | 行数 |
|-----|------|------|
| init.sql | 33 KB | 698 |
| README.md | 6.4 KB | 200+ |
| DATABASE.md | 11 KB | 400+ |
| **总计** | **50.4 KB** | **1300+** |

## 后续工作清单

- [ ] 修改默认密码
- [ ] 配置应用配置文件
- [ ] 部署数据库
- [ ] 验证表结构完整性
- [ ] 测试应用正常启动
- [ ] 创建数据库备份
- [ ] 设置定时备份任务
- [ ] 配置日志清理策略

## 相关文档

- [数据库初始化指南](README.md) - 详细的安装步骤
- [数据库结构参考](DATABASE.md) - 完整的技术文档
- [项目README](../README.md) - 项目总体介绍
- [部署指南](../README.md#部署指南) - 各种部署方式

## FAQ

### Q: 可以修改默认表结构吗？
**A**: 可以。但建议通过模型代码和 GORM 迁移来管理表结构变化，而不是直接修改 SQL 文件。

### Q: 如何添加新表？
**A**:
1. 在对应的模型文件中定义新结构
2. 应用启动时会自动迁移
3. 将变更记录到新的 migration 文件中

### Q: 初始化脚本可以重复运行吗？
**A**: 可以。脚本使用了 `CREATE TABLE IF NOT EXISTS`，重复执行不会出错。但会跳过已存在的表。

### Q: 如何备份数据？
**A**:
```bash
mysqldump -u root -p opshub > opshub_backup.sql
```

### Q: 如何恢复数据？
**A**:
```bash
mysql -u root -p opshub < opshub_backup.sql
```

## 支持

如有问题，请提交 Issue 或 PR:
- GitHub: https://github.com/ydcloud-dy/opshub/issues

---

**最后更新**: 2026-01-26
**维护者**: OpsHub Team
**许可证**: MIT License
