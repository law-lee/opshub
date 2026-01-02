package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	rbacBiz "github.com/ydcloud-dy/opshub/internal/biz/rbac"
	rbacData "github.com/ydcloud-dy/opshub/internal/data/rbac"
)

// GetCurrentUserID 从 gin.Context 获取当前登录用户的 ID
// 返回 userID 和 是否成功，如果失败会自动向客户端返回错误响应
func GetCurrentUserID(c *gin.Context) (uint, bool) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "未授权：无法获取用户信息",
		})
		return 0, false
	}

	currentUserID, ok := userIDVal.(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "用户ID类型错误",
		})
		return 0, false
	}

	return currentUserID, true
}

// RequireAdmin 检查当前用户是否为管理员
// 返回 是否为管理员，如果不是管理员会自动向客户端返回错误响应
func RequireAdmin(c *gin.Context, db *gorm.DB) bool {
	userID, ok := GetCurrentUserID(c)
	if !ok {
		return false
	}

	// 创建 RoleUseCase 来查询用户角色
	roleRepo := rbacData.NewRoleRepo(db)
	roleUseCase := rbacBiz.NewRoleUseCase(roleRepo)

	roles, err := roleUseCase.GetByUserID(context.Background(), userID)
	if err != nil {
		// 输出详细错误日志便于调试
		fmt.Printf("获取用户角色失败: userID=%d, error=%v\n", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    500,
			"message": "获取用户角色失败: " + err.Error(),
		})
		return false
	}

	// 检查是否有admin角色
	for _, role := range roles {
		if role.Code == "admin" {
			return true
		}
	}

	// 不是管理员，返回权限不足
	c.JSON(http.StatusForbidden, gin.H{
		"code":    403,
		"message": "权限不足：此操作仅限管理员执行",
	})
	return false
}

// HandleK8sError 处理 K8s API 错误，返回友好的错误提示
func HandleK8sError(c *gin.Context, err error, resourceName string) {
	if err == nil {
		return
	}

	errorMsg := err.Error()

	// 权限不足错误 (403 Forbidden)
	if strings.Contains(errorMsg, "forbidden") {
		c.JSON(http.StatusForbidden, gin.H{
			"code":    403,
			"message": "权限不足：您没有访问" + resourceName + "的权限，请联系管理员在「集群授权」中为您分配相应角色",
		})
		return
	}

	// 资源不存在错误 (404 Not Found)
	if strings.Contains(errorMsg, "not found") {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    404,
			"message": resourceName + "不存在",
		})
		return
	}

	// 未授权错误 (401 Unauthorized)
	if strings.Contains(errorMsg, "Unauthorized") {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    401,
			"message": "认证失败：凭据无效或已过期，请重新申请集群访问凭据",
		})
		return
	}

	// 其他错误
	c.JSON(http.StatusInternalServerError, gin.H{
		"code":    500,
		"message": "操作失败: " + errorMsg,
	})
}

// calculateAge 计算资源年龄
func calculateAge(creationTime time.Time) string {
	duration := time.Since(creationTime)

	days := int(duration.Hours() / 24)
	hours := int(duration.Hours())
	minutes := int(duration.Minutes())

	if days > 0 {
		if days == 1 {
			return "1d"
		}
		return strconv.Itoa(days) + "d"
	}

	if hours > 0 {
		if hours == 1 {
			return "1h"
		}
		return strconv.Itoa(hours) + "h"
	}

	if minutes > 0 {
		if minutes == 1 {
			return "1m"
		}
		return strconv.Itoa(minutes) + "m"
	}

	return "<1m"
}
