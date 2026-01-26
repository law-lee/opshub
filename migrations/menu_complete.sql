-- OpsHub 菜单修复和验证脚本
-- 这个脚本包含了菜单的所有操作：验证、重置、初始化
-- 使用方式：mysql -u root -p opshub < menu_complete.sql

-- ============================================================
-- 第一部分：验证当前菜单结构
-- ============================================================

-- 显示当前菜单列表（树形显示）
SELECT
  CONCAT(REPEAT('  ', IF(parent_id=0, 0, 1)), id, ': ', name) AS menu_tree,
  parent_id,
  type,
  sort,
  status,
  visible
FROM sys_menu
ORDER BY parent_id, sort, id;

-- ============================================================
-- 第二部分：检查菜单层级关系是否正确
-- ============================================================

-- 检查parent_id引用的菜单是否存在
SELECT
  m.id,
  m.name,
  m.parent_id,
  IF(p.id IS NULL AND m.parent_id != 0, '❌ ERROR: Parent菜单不存在', '✓ OK') as status
FROM sys_menu m
LEFT JOIN sys_menu p ON m.parent_id = p.id
ORDER BY m.id;

-- 查看系统管理下的子菜单
SELECT
  CONCAT('系统管理 (ID=5) -> ', name) as menu_structure,
  id,
  parent_id,
  sort
FROM sys_menu
WHERE parent_id = 5
ORDER BY sort;

-- ============================================================
-- 第三部分：如果上面的查询显示菜单结构不正确，执行以下重置
-- ============================================================

-- 禁用外键检查
SET FOREIGN_KEY_CHECKS = 0;

-- 清理旧菜单关联和数据
DELETE FROM sys_role_menu;
DELETE FROM sys_menu;

-- 重新启用外键
SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- 第四部分：重新初始化所有菜单（正确的结构）
-- ============================================================

INSERT INTO `sys_menu` (`id`, `name`, `code`, `type`, `parent_id`, `path`, `component`, `icon`, `sort`, `visible`, `status`, `created_at`, `updated_at`)
VALUES
  -- ========== 一级菜单（顶级）==========
  (1, '仪表盘', 'dashboard', 2, 0, '/', 'views/Index.vue', 'HomeFilled', 0, 1, 1, NOW(), NOW()),
  (2, '容器管理', 'kubernetes', 1, 0, '/kubernetes', NULL, 'Platform', 1, 1, 1, NOW(), NOW()),
  (3, '监控中心', 'monitor', 1, 0, '/monitor', NULL, 'Monitor', 2, 1, 1, NOW(), NOW()),
  (4, '任务中心', 'task', 1, 0, '/task', NULL, 'Tools', 3, 1, 1, NOW(), NOW()),
  (5, '系统管理', 'system', 1, 0, '/system', NULL, 'Setting', 100, 1, 1, NOW(), NOW()),
  (10, '权限管理', 'permission', 1, 0, '/permission', NULL, 'Lock', 101, 1, 1, NOW(), NOW()),
  (12, '资产管理', 'asset', 1, 0, '/asset', NULL, 'Connection', 102, 1, 1, NOW(), NOW()),
  (14, '审计日志', 'audit', 1, 0, '/audit', NULL, 'Document', 103, 1, 1, NOW(), NOW()),

  -- ========== 系统管理的子菜单 (parent_id=5) ==========
  (6, '用户管理', 'user', 2, 5, '/system/user', 'views/system/User.vue', 'User', 1, 1, 1, NOW(), NOW()),
  (7, '角色管理', 'role', 2, 5, '/system/role', 'views/system/Role.vue', 'UserFilled', 2, 1, 1, NOW(), NOW()),
  (8, '部门管理', 'department', 2, 5, '/system/department', 'views/system/Department.vue', 'OfficeBuilding', 3, 1, 1, NOW(), NOW()),
  (9, '菜单管理', 'menu', 2, 5, '/system/menu', 'views/system/Menu.vue', 'Menu', 4, 1, 1, NOW(), NOW()),

  -- ========== 权限管理的子菜单 (parent_id=10) ==========
  (11, '角色权限', 'role_permission', 2, 10, '/permission/role', 'views/permission/RolePermission.vue', 'Lock', 1, 1, 1, NOW(), NOW()),

  -- ========== 资产管理的子菜单 (parent_id=12) ==========
  (13, '资产列表', 'asset_list', 2, 12, '/asset/list', 'views/asset/AssetList.vue', 'Connection', 1, 1, 1, NOW(), NOW()),

  -- ========== 审计日志的子菜单 (parent_id=14) ==========
  (15, '操作日志', 'operation_log', 2, 14, '/audit/operation', 'views/audit/OperationLog.vue', 'Document', 1, 1, 1, NOW(), NOW()),
  (16, '登录日志', 'login_log', 2, 14, '/audit/login', 'views/audit/LoginLog.vue', 'Document', 2, 1, 1, NOW(), NOW());

-- ============================================================
-- 第五部分：重新关联角色和菜单权限
-- ============================================================

-- 为管理员角色分配所有菜单权限
INSERT INTO `sys_role_menu` (`role_id`, `menu_id`)
VALUES
  (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8), (1, 9),
  (1, 10), (1, 11), (1, 12), (1, 13), (1, 14), (1, 15), (1, 16);

-- 为普通用户角色分配基础菜单权限
INSERT INTO `sys_role_menu` (`role_id`, `menu_id`)
VALUES
  (2, 1), (2, 2), (2, 3), (2, 4), (2, 12), (2, 13), (2, 14), (2, 15), (2, 16);

-- ============================================================
-- 第六部分：验证菜单重置是否成功
-- ============================================================

-- 再次显示正确的菜单结构
SELECT '========== 菜单重置完成 ==========' as message;
SELECT
  CONCAT(REPEAT('  ', IF(parent_id=0, 0, 1)), id, ': ', name) AS menu_tree,
  parent_id,
  type,
  sort,
  status,
  visible
FROM sys_menu
ORDER BY parent_id, sort, id;

-- 统计菜单数量
SELECT '========== 菜单统计 ==========' as message;
SELECT
  type,
  COUNT(*) as count,
  CASE type
    WHEN 1 THEN '一级菜单（目录）'
    WHEN 2 THEN '二级菜单（菜单项）'
    WHEN 3 THEN '三级菜单（按钮）'
  END as type_name
FROM sys_menu
GROUP BY type;

-- 检查系统管理是否有正确的子菜单
SELECT '========== 系统管理子菜单检查 ==========' as message;
SELECT COUNT(*) as child_count
FROM sys_menu
WHERE parent_id = 5;

-- 如果以上都显示正确，菜单已经成功重置！
SELECT '========== ✓ 菜单重置成功 ==========' as message;
SELECT '请执行以下步骤完成修复：' as next_step;
SELECT '1. 清除浏览器缓存 (Ctrl+Shift+Delete)' as step;
SELECT '2. 重启后端应用' as step;
SELECT '3. 重新登录系统' as step;
