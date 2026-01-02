-- OpsHub 数据库初始化脚本
-- 用途：创建数据库和基础表结构
-- 注意：表结构会通过 GORM AutoMigrate 自动创建，此脚本主要用于创建数据库

-- 创建数据库（如果不存在）
CREATE DATABASE IF NOT EXISTS `opshub` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- 使用数据库
USE `opshub`;

-- 禁用外键检查（GORM 已在迁移时禁用外键约束）
SET FOREIGN_KEY_CHECKS = 0;

-- 以下表会由 GORM AutoMigrate 自动创建：
-- - sys_user (用户表)
-- - sys_role (角色表)
-- - sys_department (部门表)
-- - sys_menu (菜单表)
-- - sys_user_role (用户角色关联表)
-- - sys_role_menu (角色菜单关联表)
-- - k8s_clusters (Kubernetes 集群表)
-- - k8s_user_kube_configs (用户 KubeConfig 凭据表)
-- - k8s_user_role_bindings (用户 K8s 角色绑定表)

-- 恢复外键检查
SET FOREIGN_KEY_CHECKS = 1;

-- 说明：
-- 1. 表结构会在服务启动时通过 GORM AutoMigrate 自动创建和更新
-- 2. 默认数据（管理员账号、角色、菜单）会在首次启动时自动初始化
-- 3. 默认管理员账号：admin / 123456
