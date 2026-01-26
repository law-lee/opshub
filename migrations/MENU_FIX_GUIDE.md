# 菜单结构修复指南

## 问题描述

在另一台机器运行后，菜单结构显示错误：
- 用户管理、角色管理、部门管理、菜单管理显示为**顶级菜单**
- 应该显示为**系统管理**的**子菜单**

## 根本原因

这通常是因为：
1. 使用了旧的数据库初始化脚本
2. 数据库中还有旧的菜单数据
3. 菜单的 `parent_id` 关系设置不正确

## 完整的修复步骤

### 方法 1: 快速修复（推荐）- 只需一个命令

```bash
# 执行完整的菜单修复脚本
mysql -u root -p opshub < migrations/menu_complete.sql
```

这个脚本会：
1. ✓ 显示当前菜单结构（用于诊断）
2. ✓ 检查菜单层级关系是否正确
3. ✓ 清理旧菜单数据
4. ✓ 重新初始化所有菜单（正确的结构）
5. ✓ 重新关联角色权限
6. ✓ 验证修复是否成功

然后按照脚本最后的提示完成以下步骤：

```bash
# 1. 清除浏览器缓存
# 按 Ctrl+Shift+Delete 清除所有缓存

# 2. 重启应用
pkill -f "go run main.go"
go run main.go server

# 3. 重新登录系统
```

### 方法 2: 手动修复（不推荐，用于调试）

如果上面的方法不行，可以手动检查和修复菜单数据。

#### 检查当前菜单状态

```sql
-- 查看所有菜单的层级关系
SELECT id, name, parent_id, sort, type, status
FROM sys_menu
ORDER BY parent_id, sort;

-- 检查"系统管理"（ID=5）下的菜单
SELECT id, name, parent_id
FROM sys_menu
WHERE parent_id = 5;
```

#### 手动修复 parent_id

如果上面的查询显示为空，说明子菜单的 parent_id 设置错误，需要手动更新：

```sql
-- 更新"用户管理"菜单
UPDATE sys_menu SET parent_id = 5 WHERE code = 'user';

-- 更新"角色管理"菜单
UPDATE sys_menu SET parent_id = 5 WHERE code = 'role';

-- 更新"部门管理"菜单
UPDATE sys_menu SET parent_id = 5 WHERE code = 'department';

-- 更新"菜单管理"菜单
UPDATE sys_menu SET parent_id = 5 WHERE code = 'menu';
```

#### 验证修复

重新运行上面的查询，应该能看到4条记录。

### 方法 3: 完全重新初始化数据库（最安全）

如果前两种方法都不行，可以重新初始化整个数据库：

```bash
# 1. 删除旧数据库
mysql -u root -p -e "DROP DATABASE opshub;"

# 2. 创建新数据库
mysql -u root -p -e "CREATE DATABASE opshub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# 3. 导入最新的初始化脚本
mysql -u root -p opshub < migrations/init.sql

# 4. 验证菜单结构
mysql -u root -p opshub < migrations/verify_menus.sql
```

## 菜单结构说明

正确的菜单结构应该是这样的：

```
├─ 仪表盘 (sort=0, parent_id=0)
│
├─ 容器管理 (sort=1, parent_id=0) ← 插件菜单
│
├─ 监控中心 (sort=2, parent_id=0) ← 插件菜单
│
├─ 任务中心 (sort=3, parent_id=0) ← 插件菜单
│
├─ 系统管理 (sort=100, parent_id=0)
│  ├─ 用户管理 (sort=1, parent_id=5)
│  ├─ 角色管理 (sort=2, parent_id=5)
│  ├─ 部门管理 (sort=3, parent_id=5)
│  └─ 菜单管理 (sort=4, parent_id=5)
│
├─ 权限管理 (sort=101, parent_id=0)
│  └─ 角色权限 (sort=1, parent_id=10)
│
├─ 资产管理 (sort=102, parent_id=0)
│  └─ 资产列表 (sort=1, parent_id=12)
│
└─ 审计日志 (sort=103, parent_id=0)
   ├─ 操作日志 (sort=1, parent_id=14)
   └─ 登录日志 (sort=2, parent_id=14)
```

## 关键点

### 菜单 ID 分配

- **1-4**: 顶级菜单（仪表盘、容器管理、监控中心、任务中心）
- **5**: 系统管理
- **6-9**: 系统管理的子菜单
- **10-11**: 权限管理及其子菜单
- **12-13**: 资产管理及其子菜单
- **14-16**: 审计日志及其子菜单

### parent_id 的含义

- `parent_id = 0`: 顶级菜单
- `parent_id = 5`: 系统管理的子菜单
- `parent_id = 10`: 权限管理的子菜单
- `parent_id = 12`: 资产管理的子菜单
- `parent_id = 14`: 审计日志的子菜单

### 更新 init.sql 的方式

如果你需要修改 `migrations/init.sql` 中的菜单结构，确保：

1. 子菜单的 `parent_id` 指向正确的父菜单 ID
2. 同级菜单的 `sort` 按递增顺序排列
3. 菜单的 `type` 值正确：
   - `type=1`: 目录/分类
   - `type=2`: 菜单项
   - `type=3`: 按钮
4. 子菜单必须在 `sys_role_menu` 表中有相应的权限记录

## 故障排查

### 问题：菜单仍然显示不正确

1. **检查浏览器缓存**
   ```bash
   # 在浏览器中按 Ctrl+Shift+Delete（Windows/Linux）或 Cmd+Shift+Delete（Mac）
   # 清除所有缓存数据
   ```

2. **检查数据库连接**
   ```bash
   mysql -u root -p opshub -e "SHOW TABLES;"
   ```

3. **查看应用日志**
   ```bash
   # 如果有日志文件，查看是否有错误
   tail -f logs/app.log
   ```

4. **重启应用**
   ```bash
   pkill -f "go run main.go"
   go run main.go server
   ```

### 问题：菜单权限设置有问题

检查 `sys_role_menu` 表中是否有对应的权限记录：

```sql
-- 查看管理员角色（id=1）的菜单权限
SELECT rm.role_id, rm.menu_id, m.name
FROM sys_role_menu rm
JOIN sys_menu m ON rm.menu_id = m.id
WHERE rm.role_id = 1
ORDER BY m.sort;
```

应该包含所有菜单的权限。

## 相关文件

- `migrations/init.sql` - 完整的数据库初始化脚本
- `migrations/reset_menus.sql` - 菜单重置脚本
- `migrations/verify_menus.sql` - 菜单验证脚本
- `migrations/MENU_CONFIG.md` - 菜单配置文档

## 支持

如有问题，请：
1. 检查本指南中的故障排查部分
2. 查看应用日志
3. 提交 Issue: https://github.com/ydcloud-dy/opshub/issues

---

**最后更新**: 2026-01-26
