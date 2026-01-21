package asset

import (
	"time"

	"gorm.io/gorm"
)

// TerminalSession SSH终端会话模型
type TerminalSession struct {
	ID            uint           `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"deletedAt,omitempty"`
	HostID        uint           `gorm:"column:host_id;not null;comment:主机ID" json:"hostId"`
	HostName      string         `gorm:"type:varchar(100);comment:主机名称" json:"hostName"`
	HostIP        string         `gorm:"type:varchar(50);comment:主机IP" json:"hostIp"`
	UserID        uint           `gorm:"column:user_id;not null;comment:操作用户ID" json:"userId"`
	Username      string         `gorm:"type:varchar(100);comment:用户名" json:"username"`
	RecordingPath string         `gorm:"type:varchar(500);comment:录制文件路径" json:"recordingPath"`
	Duration      int            `gorm:"type:int;comment:会话时长(秒)" json:"duration"`
	FileSize      int64          `gorm:"type:bigint;comment:文件大小(字节)" json:"fileSize"`
	Status        string         `gorm:"type:varchar(20);default:'recording';comment:会话状态 recording/completed/failed" json:"status"`
}

// TableName 表名
func (TerminalSession) TableName() string {
	return "ssh_terminal_sessions"
}

// TerminalSessionInfo 终端会话信息VO
type TerminalSessionInfo struct {
	ID            uint      `json:"id"`
	HostID        uint      `json:"hostId"`
	HostName      string    `json:"hostName"`
	HostIP        string    `json:"hostIp"`
	UserID        uint      `json:"userId"`
	Username      string    `json:"username"`
	Duration      int       `json:"duration"`
	DurationText  string    `json:"durationText"`  // 格式化的时长，如 "1m 30s"
	FileSize      int64     `json:"fileSize"`
	FileSizeText  string    `json:"fileSizeText"`  // 格式化的文件大小，如 "1.5 MB"
	Status        string    `json:"status"`
	StatusText    string    `json:"statusText"`
	CreatedAt     time.Time `json:"createdAt"`
	CreatedAtText string    `json:"createdAtText"` // 格式化的创建时间
}

// TerminalSessionListRequest 终端会话列表请求
type TerminalSessionListRequest struct {
	Page     int    `form:"page" binding:"required,min=1"`
	PageSize int    `form:"pageSize" binding:"required,min=1,max=100"`
	Keyword  string `form:"keyword"` // 搜索关键词（主机名、IP）
}

// TerminalSessionListResponse 终端会话列表响应
type TerminalSessionListResponse struct {
	Total int64                  `json:"total"`
	List  []*TerminalSessionInfo `json:"list"`
}
