package rbac

import (
	"time"

	"gorm.io/gorm"
)

// SysUser 用户表
type SysUser struct {
	gorm.Model
	Username    string         `gorm:"type:varchar(50);not null;comment:用户名" json:"username"`
	Password    string         `gorm:"type:varchar(255);not null;comment:密码" json:"password,omitempty"`
	RealName    string         `gorm:"type:varchar(50);comment:真实姓名" json:"realName"`
	Email       string         `gorm:"type:varchar(100);comment:邮箱" json:"email"`
	Phone       string         `gorm:"type:varchar(20);comment:手机号" json:"phone"`
	Avatar      string         `gorm:"type:varchar(255);comment:头像" json:"avatar"`
	Status      int            `gorm:"type:tinyint;default:1;comment:状态 1:启用 0:禁用" json:"status"`
	DepartmentID uint          `gorm:"default:0;comment:部门ID" json:"departmentId"`
	Department  *SysDepartment `gorm:"foreignKey:DepartmentID;references:ID" json:"department,omitempty"`
	Roles       []SysRole      `gorm:"many2many:sys_user_roles" json:"roles"`
	LastLoginAt *time.Time     `gorm:"comment:最后登录时间" json:"lastLoginAt,omitempty"`
}

// SysRole 角色表
type SysRole struct {
	gorm.Model
	Name        string       `gorm:"type:varchar(50);uniqueIndex;not null;comment:角色名称" json:"name"`
	Code        string       `gorm:"type:varchar(50);uniqueIndex;not null;comment:角色编码" json:"code"`
	Description string       `gorm:"type:varchar(200);comment:角色描述" json:"description"`
	Sort        int          `gorm:"type:int;default:0;comment:排序" json:"sort"`
	Status      int          `gorm:"type:tinyint;default:1;comment:状态 1:启用 0:禁用" json:"status"`
	Users       []SysUser    `gorm:"many2many:sys_user_roles" json:"-"`
	Menus       []SysMenu    `gorm:"many2many:sys_role_menus" json:"menus,omitempty"`
}

// SysDepartment 部门表
type SysDepartment struct {
	gorm.Model
	Name        string            `gorm:"type:varchar(50);not null;comment:部门名称" json:"name"`
	Code        string            `gorm:"type:varchar(50);uniqueIndex;comment:部门编码" json:"code"`
	ParentID    uint              `gorm:"default:0;comment:父部门ID" json:"parentId"`
	Parent      *SysDepartment    `gorm:"-" json:"parent,omitempty"`
	Children    []*SysDepartment   `gorm:"-" json:"children,omitempty"`
	Sort        int               `gorm:"type:int;default:0;comment:排序" json:"sort"`
	Status      int               `gorm:"type:tinyint;default:1;comment:状态 1:启用 0:禁用" json:"status"`
}

// SysMenu 菜单表
type SysMenu struct {
	gorm.Model
	Name        string        `gorm:"type:varchar(50);not null;comment:菜单名称" json:"name"`
	Code        string        `gorm:"type:varchar(50);uniqueIndex;comment:菜单编码" json:"code"`
	Type        int           `gorm:"type:tinyint;not null;comment:类型 1:目录 2:菜单 3:按钮" json:"type"`
	ParentID    uint          `gorm:"default:0;comment:父菜单ID" json:"parentId"`
	Parent      *SysMenu      `gorm:"-" json:"parent,omitempty"`
	Children    []*SysMenu     `gorm:"-" json:"children,omitempty"`
	Path        string        `gorm:"type:varchar(200);comment:路由路径" json:"path"`
	Component   string        `gorm:"type:varchar(200);comment:组件路径" json:"component"`
	Icon        string        `gorm:"type:varchar(100);comment:图标" json:"icon"`
	Sort        int           `gorm:"type:int;default:0;comment:排序" json:"sort"`
	Visible     int           `gorm:"type:tinyint;default:1;comment:是否显示 1:显示 0:隐藏" json:"visible"`
	Status      int           `gorm:"type:tinyint;default:1;comment:状态 1:启用 0:禁用" json:"status"`
	Roles       []SysRole     `gorm:"many2many:sys_role_menus" json:"-"`
}

// SysUserRole 用户角色关联表
type SysUserRole struct {
	UserID uint `gorm:"primaryKey;comment:用户ID" json:"userId"`
	RoleID uint `gorm:"primaryKey;comment:角色ID" json:"roleId"`
}

// SysRoleMenu 角色菜单关联表
type SysRoleMenu struct {
	RoleID uint `gorm:"primaryKey;comment:角色ID" json:"roleId"`
	MenuID uint `gorm:"primaryKey;comment:菜单ID" json:"menuId"`
}

// TableName 指定表名
func (SysUser) TableName() string {
	return "sys_user"
}

func (SysRole) TableName() string {
	return "sys_role"
}

func (SysDepartment) TableName() string {
	return "sys_department"
}

func (SysMenu) TableName() string {
	return "sys_menu"
}

func (SysUserRole) TableName() string {
	return "sys_user_role"
}

func (SysRoleMenu) TableName() string {
	return "sys_role_menu"
}
