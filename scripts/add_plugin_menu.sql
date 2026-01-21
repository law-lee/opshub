-- 添加插件管理菜单 (MySQL)

-- 1. 插件管理（父菜单）
INSERT IGNORE INTO sys_menu (name, code, type, parent_id, path, component, icon, sort, visible, status) VALUES
('插件管理', 'plugin', 1, 0, '/plugin', '', 'Grid', 80, 1, 1);

-- 获取父菜单ID
SET @plugin_parent_id = (SELECT id FROM sys_menu WHERE code = 'plugin' LIMIT 1);

-- 2. 插件管理子菜单
INSERT IGNORE INTO sys_menu (name, code, type, parent_id, path, component, icon, sort, visible, status) VALUES
('插件列表', 'plugin-list', 2, @plugin_parent_id, '/plugin/list', 'plugin/PluginList', 'Grid', 1, 1, 1),
('插件安装', 'plugin-install', 2, @plugin_parent_id, '/plugin/install', 'plugin/PluginInstall', 'Upload', 2, 1, 1);

-- 3. 为角色ID=1的超级管理员分配插件管理菜单权限
INSERT IGNORE INTO sys_role_menu (role_id, menu_id)
SELECT 1, id FROM sys_menu WHERE code IN ('plugin', 'plugin-list', 'plugin-install');
