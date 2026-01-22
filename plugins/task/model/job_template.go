package model

import (
	"time"
)

// JobTemplate 任务模板
type JobTemplate struct {
	ID          uint       `json:"id" gorm:"primaryKey"`
	Name        string     `json:"name" gorm:"size:255;not null" binding:"required"`
	Code        string     `json:"code" gorm:"size:100;not null;uniqueIndex" binding:"required"`
	Description string     `json:"description" gorm:"type:text"`
	Content     string     `json:"content" gorm:"type:longtext;not null" binding:"required"`
	Variables   string     `json:"variables,omitempty" gorm:"type:text"` // JSON字符串
	Category    string     `json:"category" gorm:"size:50;not null;index" binding:"required"` // script, ansible, module
	Platform    string     `json:"platform,omitempty" gorm:"size:50"` // linux, windows
	Timeout     int        `json:"timeout" gorm:"default:300"` // 秒
	Sort        int        `json:"sort" gorm:"default:0;index"`
	Status      int        `json:"status" gorm:"default:1;index"` // 0-禁用, 1-启用
	CreatedBy   uint       `json:"createdBy" gorm:"not null"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	DeletedAt   *time.Time `json:"deletedAt,omitempty" gorm:"index"`
}

func (JobTemplate) TableName() string {
	return "job_templates"
}
