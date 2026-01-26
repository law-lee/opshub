# OpsHub 菜单排序配置说明

## 菜单结构层级

OpsHub 系统使用三级菜单结构，通过 `sort` 字段控制显示顺序。

### 菜单层级说明

| 级别 | type值 | 说明 | 示例 |
|-----|--------|------|------|
| 一级 | 1 | 目录/分类 | 容器管理、监控中心 |
| 二级 | 2 | 实际菜单项 | 用户管理、资产列表 |
| 三级 | 3 | 按钮/操作 | 新建、编辑、删除 |

## 当前菜单排序

### 顶级菜单排序 (type=1, parent_id=0)

```
sort=0   → 仪表盘 (code: dashboard)
sort=1   → 容器管理 (code: kubernetes) ★ 插件菜单
sort=2   → 监控中心 (code: monitor) ★ 插件菜单
sort=3   → 任务中心 (code: task) ★ 插件菜单
sort=100 → 系统管理 (code: system)
sort=101 → 权限管理 (code: permission)
sort=102 → 资产管理 (code: asset)
sort=103 → 审计日志 (code: audit)
```

### 子菜单排序 (type=2)

**系统管理下的子菜单** (parent_id=5):
```
sort=1 → 用户管理
sort=2 → 角色管理
sort=3 → 部门管理
sort=4 → 菜单管理
```

**权限管理下的子菜单** (parent_id=10):
```
sort=1 → 角色权限
```

**资产管理下的子菜单** (parent_id=12):
```
sort=1 → 资产列表
```

**审计日志下的子菜单** (parent_id=14):
```
sort=1 → 操作日志
sort=2 → 登录日志
```

## 菜单可视化结构

```
┌─ 仪表盘 (sort=0)
│
├─ 容器管理 (sort=1) ★
│  └─ [子菜单由插件动态生成]
│
├─ 监控中心 (sort=2) ★
│  └─ [子菜单由插件动态生成]
│
├─ 任务中心 (sort=3) ★
│  └─ [子菜单由插件动态生成]
│
├─ 系统管理 (sort=100)
│  ├─ 用户管理 (sort=1)
│  ├─ 角色管理 (sort=2)
│  ├─ 部门管理 (sort=3)
│  └─ 菜单管理 (sort=4)
│
├─ 权限管理 (sort=101)
│  └─ 角色权限 (sort=1)
│
├─ 资产管理 (sort=102)
│  └─ 资产列表 (sort=1)
│
└─ 审计日志 (sort=103)
   ├─ 操作日志 (sort=1)
   └─ 登录日志 (sort=2)
```

## 修改菜单排序的方式

### 方式一：直接修改数据库

```sql
-- 修改菜单的排序
UPDATE sys_menu SET sort=2 WHERE code='kubernetes';
UPDATE sys_menu SET sort=3 WHERE code='monitor';
UPDATE sys_menu SET sort=4 WHERE code='task';
```

### 方式二：通过管理界面

1. 登录系统
2. 进入「系统管理」→「菜单管理」
3. 编辑菜单的排序字段
4. 保存修改

### 方式三：修改初始化脚本

编辑 `migrations/init.sql` 中的菜单插入语句，修改 `sort` 的值。

## 插件菜单集成

### 插件菜单的 sort 值建议

| 级别 | 推荐sort值 | 说明 |
|-----|-----------|------|
| 一级菜单 | 1-99 | 插件的主菜单 |
| 二级菜单 | 1-10 | 插件内的子功能 |

### 示例：Kubernetes 插件菜单

```sql
-- 容器管理下的子菜单（由插件添加）
(parent_id=2, code='cluster_management', sort=1, name='集群管理')
(parent_id=2, code='node_management', sort=2, name='节点管理')
(parent_id=2, code='workload_management', sort=3, name='工作负载')
-- ... 其他子菜单
```

## 性能提示

1. **查询优化**：在频繁查询菜单的字段上建立索引
   ```sql
   CREATE INDEX idx_menu_sort ON sys_menu(sort);
   CREATE INDEX idx_menu_parent ON sys_menu(parent_id, sort);
   ```

2. **缓存策略**：菜单数据相对稳定，建议在应用启动时缓存

3. **更新范围**：修改菜单排序后，需要清除缓存并刷新页面

## 常见问题

### Q: 为什么插件菜单不显示？
**A**: 检查以下几点：
1. 插件是否已启用 (status=1)
2. 菜单的 parent_id 是否指向正确的插件
3. 用户角色是否有该菜单的权限
4. 检查是否有 soft delete (deleted_at IS NULL)

### Q: 为什么菜单显示不在系统管理下面？
**A**: 这个常见的问题通常是因为菜单的 `parent_id` 设置错误。请按以下步骤检查和修复：

**步骤 1: 验证菜单结构**
```bash
mysql -u root -p opshub < migrations/verify_menus.sql
```

**步骤 2: 查看结果中的"系统管理下的子菜单"部分**
- 应该显示用户管理、角色管理、部门管理、菜单管理
- 这些菜单的 parent_id 应该都是 5

**步骤 3: 如果显示不正确，执行菜单重置脚本**
```bash
mysql -u root -p opshub < migrations/reset_menus.sql
```

**步骤 4: 刷新应用**
- 清除浏览器缓存
- 重启应用服务
- 重新登录

### Q: 系统管理菜单下的子菜单为什么显示为顶级菜单？
**A**: 这表示数据库中的菜单 parent_id 关系不正确。原因可能是：

1. **使用了旧的初始化脚本** - 确保使用的是最新的 init.sql
2. **数据库没有完全清理** - 使用 reset_menus.sql 重置菜单
3. **后端和前端版本不匹配** - 确保后端和前端代码版本一致

**快速修复**:
```sql
-- 检查系统管理（ID=5）的子菜单
SELECT id, name, parent_id FROM sys_menu WHERE parent_id = 5;

-- 应该返回：
-- 6, 用户管理, 5
-- 7, 角色管理, 5
-- 8, 部门管理, 5
-- 9, 菜单管理, 5

-- 如果为空，说明parent_id设置错误，需要更新：
UPDATE sys_menu SET parent_id = 5 WHERE code IN ('user', 'role', 'department', 'menu');
```

### Q: 如何调整菜单的显示顺序？
**A**: 修改 `sort` 值，数值越小越靠前显示

### Q: 为什么修改 sort 后菜单顺序没变？
**A**: 可能原因：
1. 缓存未清除
2. 需要刷新页面或重启应用
3. 前端缓存需要清除（浏览器缓存/本地存储）

## 相关SQL查询

### 查看完整的菜单树

```sql
SELECT
    m1.id,
    m1.code,
    m1.name,
    m1.sort,
    m1.type,
    CONCAT('Level 1: ', m1.name) as level1,
    GROUP_CONCAT(m2.name) as children
FROM sys_menu m1
LEFT JOIN sys_menu m2 ON m1.id = m2.parent_id AND m2.deleted_at IS NULL
WHERE m1.parent_id = 0 AND m1.deleted_at IS NULL
GROUP BY m1.id
ORDER BY m1.sort ASC;
```

### 查看用户可访问的菜单

```sql
SELECT DISTINCT m.id, m.name, m.sort, m.path, m.icon
FROM sys_menu m
INNER JOIN sys_role_menu rm ON m.id = rm.menu_id
INNER JOIN sys_user_role ur ON rm.role_id = ur.role_id
WHERE ur.user_id = 1 -- 用户ID
  AND m.deleted_at IS NULL
ORDER BY m.parent_id, m.sort;
```

### 统计菜单数量

```sql
-- 统计各级菜单数量
SELECT
    type,
    COUNT(*) as count,
    CASE type
        WHEN 1 THEN '一级菜单'
        WHEN 2 THEN '二级菜单'
        WHEN 3 THEN '按钮/操作'
    END as type_name
FROM sys_menu
WHERE deleted_at IS NULL
GROUP BY type;
```

## 菜单权限配置

### 给角色添加菜单权限

```sql
-- 为"普通用户"角色添加"容器管理"菜单权限
INSERT INTO sys_role_menu (role_id, menu_id) VALUES (2, 2);

-- 为"普通用户"角色添加所有一级菜单
INSERT INTO sys_role_menu (role_id, menu_id)
SELECT 2, id FROM sys_menu WHERE type=1 AND deleted_at IS NULL;
```

### 为菜单添加子功能

```sql
-- 添加新的二级菜单
INSERT INTO sys_menu (name, code, type, parent_id, path, sort, status)
VALUES ('日志查询', 'log_query', 2, 14, '/audit/query', 3, 1);

-- 为所有角色授予该菜单权限
INSERT INTO sys_role_menu (role_id, menu_id)
SELECT id, LAST_INSERT_ID() FROM sys_role WHERE deleted_at IS NULL;
```

## 最佳实践

1. **命名规范**：使用英文 code，便于前端识别
2. **排序间隔**：使用 10 倍数间隔（0, 10, 20...）便于后续插入
3. **权限隔离**：敏感菜单通过角色权限严格控制
4. **缓存更新**：菜单变更后主动清除缓存
5. **文档维护**：更新菜单时同步更新此文档

## 相关文档

- [数据库初始化指南](README.md)
- [数据库结构参考](DATABASE.md)
- [OpsHub 项目主文档](../README.md)
