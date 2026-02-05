// Copyright (c) 2026 DYCloud J.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package system

import (
	"time"

	"gorm.io/gorm"
)

// SysConfig 系统配置表
type SysConfig struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Key       string         `gorm:"type:varchar(100);uniqueIndex;not null;comment:配置键" json:"key"`
	Value     string         `gorm:"type:text;comment:配置值" json:"value"`
	Type      string         `gorm:"type:varchar(20);default:'string';comment:配置类型(string/int/bool/json)" json:"type"`
	Group     string         `gorm:"type:varchar(50);index;comment:配置分组(basic/security)" json:"group"`
	Remark    string         `gorm:"type:varchar(200);comment:备注说明" json:"remark"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName 指定表名
func (SysConfig) TableName() string {
	return "sys_config"
}

// SysUserLoginAttempt 用户登录失败记录表
type SysUserLoginAttempt struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Username    string     `gorm:"type:varchar(50);index;not null;comment:用户名" json:"username"`
	FailCount   int        `gorm:"default:0;comment:失败次数" json:"failCount"`
	LastFailAt  time.Time  `gorm:"comment:最后失败时间" json:"lastFailAt"`
	LockedUntil *time.Time `gorm:"comment:锁定截止时间" json:"lockedUntil"`
}

// TableName 指定表名
func (SysUserLoginAttempt) TableName() string {
	return "sys_user_login_attempt"
}

// ConfigKey 配置键常量
const (
	// 基础配置
	ConfigKeySystemName        = "system_name"
	ConfigKeySystemLogo        = "system_logo"
	ConfigKeySystemDescription = "system_description"

	// 安全配置
	ConfigKeyPasswordMinLength = "password_min_length"
	ConfigKeySessionTimeout    = "session_timeout"
	ConfigKeyEnableCaptcha     = "enable_captcha"
	ConfigKeyMaxLoginAttempts  = "max_login_attempts"
	ConfigKeyLockoutDuration   = "lockout_duration"
)

// ConfigGroup 配置分组常量
const (
	ConfigGroupBasic    = "basic"
	ConfigGroupSecurity = "security"
)

// DefaultConfigs 默认配置
var DefaultConfigs = map[string]SysConfig{
	ConfigKeySystemName: {
		Key:    ConfigKeySystemName,
		Value:  "OpsHub",
		Type:   "string",
		Group:  ConfigGroupBasic,
		Remark: "系统名称",
	},
	ConfigKeySystemLogo: {
		Key:    ConfigKeySystemLogo,
		Value:  "",
		Type:   "string",
		Group:  ConfigGroupBasic,
		Remark: "系统Logo路径",
	},
	ConfigKeySystemDescription: {
		Key:    ConfigKeySystemDescription,
		Value:  "运维管理平台",
		Type:   "string",
		Group:  ConfigGroupBasic,
		Remark: "系统描述",
	},
	ConfigKeyPasswordMinLength: {
		Key:    ConfigKeyPasswordMinLength,
		Value:  "8",
		Type:   "int",
		Group:  ConfigGroupSecurity,
		Remark: "密码最小长度",
	},
	ConfigKeySessionTimeout: {
		Key:    ConfigKeySessionTimeout,
		Value:  "3600",
		Type:   "int",
		Group:  ConfigGroupSecurity,
		Remark: "Session超时时间(秒)",
	},
	ConfigKeyEnableCaptcha: {
		Key:    ConfigKeyEnableCaptcha,
		Value:  "true",
		Type:   "bool",
		Group:  ConfigGroupSecurity,
		Remark: "是否开启验证码",
	},
	ConfigKeyMaxLoginAttempts: {
		Key:    ConfigKeyMaxLoginAttempts,
		Value:  "5",
		Type:   "int",
		Group:  ConfigGroupSecurity,
		Remark: "最大登录失败次数",
	},
	ConfigKeyLockoutDuration: {
		Key:    ConfigKeyLockoutDuration,
		Value:  "300",
		Type:   "int",
		Group:  ConfigGroupSecurity,
		Remark: "账户锁定时间(秒)",
	},
}

// BasicConfig 基础配置响应结构
type BasicConfig struct {
	SystemName        string `json:"systemName"`
	SystemLogo        string `json:"systemLogo"`
	SystemDescription string `json:"systemDescription"`
}

// SecurityConfig 安全配置响应结构
type SecurityConfig struct {
	PasswordMinLength int  `json:"passwordMinLength"`
	SessionTimeout    int  `json:"sessionTimeout"`
	EnableCaptcha     bool `json:"enableCaptcha"`
	MaxLoginAttempts  int  `json:"maxLoginAttempts"`
	LockoutDuration   int  `json:"lockoutDuration"`
}

// AllConfig 所有配置响应结构
type AllConfig struct {
	Basic    BasicConfig    `json:"basic"`
	Security SecurityConfig `json:"security"`
}
