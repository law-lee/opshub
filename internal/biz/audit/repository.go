package audit

import (
	"context"
)

// OperationLogRepo 操作日志仓储接口
type OperationLogRepo interface {
	Create(ctx context.Context, log *SysOperationLog) error
	GetByID(ctx context.Context, id uint) (*SysOperationLog, error)
	List(ctx context.Context, page, pageSize int, username, module, action, status, startTime, endTime string) ([]*SysOperationLog, int64, error)
	Delete(ctx context.Context, id uint) error
	DeleteBatch(ctx context.Context, ids []uint) error
}

// LoginLogRepo 登录日志仓储接口
type LoginLogRepo interface {
	Create(ctx context.Context, log *SysLoginLog) error
	GetByID(ctx context.Context, id uint) (*SysLoginLog, error)
	List(ctx context.Context, page, pageSize int, username, loginType, loginStatus, startTime, endTime string) ([]*SysLoginLog, int64, error)
	UpdateLogout(ctx context.Context, userID uint, logoutTime *SysLoginLog) error
	Delete(ctx context.Context, id uint) error
	DeleteBatch(ctx context.Context, ids []uint) error
}

// DataLogRepo 数据日志仓储接口
type DataLogRepo interface {
	Create(ctx context.Context, log *SysDataLog) error
	GetByID(ctx context.Context, id uint) (*SysDataLog, error)
	List(ctx context.Context, page, pageSize int, username, tableName, action, startTime, endTime string) ([]*SysDataLog, int64, error)
	Delete(ctx context.Context, id uint) error
	DeleteBatch(ctx context.Context, ids []uint) error
}
