-- OpsHub 默认数据初始化脚本
-- 用途：初始化管理员角色和用户角色关联
-- 使用方法：在服务首次启动前执行此脚本

USE `opshub`;

-- 禁用外键检查
SET FOREIGN_KEY_CHECKS = 0;

-- 1. 创建默认管理员角色（如果不存在）
INSERT INTO `sys_role` (`id`, `name`, `code`, `description`, `sort`, `status`, `created_at`, `updated_at`)
VALUES (1, '超级管理员', 'admin', '拥有系统所有权限', 0, 1, NOW(), NOW())
ON DUPLICATE KEY UPDATE `name`='超级管理员', `description`='拥有系统所有权限';

-- 2. 确保 admin 用户存在（密码: 123456 的 bcrypt 哈希值）
-- 注意：如果 admin 用户不存在，需要先通过注册接口创建，或者手动插入
-- $2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z2EHCrDN/y4VoGW50d9wCq7

-- 3. 关联 admin 用户和 admin 角色
-- 假设 admin 用户的 ID 是 1（如果不同，请修改此处）
INSERT INTO `sys_user_role` (`user_id`, `role_id`)
VALUES (1, 1)
ON DUPLICATE KEY UPDATE `user_id`=1, `role_id`=1;

-- 恢复外键检查
SET FOREIGN_KEY_CHECKS = 1;

-- 验证数据
SELECT '=== 验证结果 ===' AS '';
SELECT u.id, u.username, u.real_name, r.code, r.name
FROM sys_user u
LEFT JOIN sys_user_role ur ON u.id = ur.user_id
LEFT JOIN sys_role r ON ur.role_id = r.id
WHERE u.username = 'admin';
