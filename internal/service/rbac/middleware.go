package rbac

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/ydcloud-dy/opshub/pkg/response"
)

const (
	UserIdKey   = "user_id"
	UsernameKey = "username"
)

// GetUserID 从上下文获取用户ID
func GetUserID(c *gin.Context) uint {
	if userID, exists := c.Get(UserIdKey); exists {
		if id, ok := userID.(uint); ok {
			return id
		}
	}
	return 0
}

// GetUsername 从上下文获取用户名
func GetUsername(c *gin.Context) string {
	if username, exists := c.Get(UsernameKey); exists {
		if name, ok := username.(string); ok {
			return name
		}
	}
	return ""
}

// AuthMiddleware JWT认证中间件
type AuthMiddleware struct {
	authService *AuthService
}

func NewAuthMiddleware(authService *AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

// AuthRequired JWT认证
func (m *AuthMiddleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.ErrorCode(c, http.StatusUnauthorized, "未登录")
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			response.ErrorCode(c, http.StatusUnauthorized, "token格式错误")
			c.Abort()
			return
		}

		claims, err := m.authService.ParseToken(parts[1])
		if err != nil {
			response.ErrorCode(c, http.StatusUnauthorized, "token无效或已过期")
			c.Abort()
			return
		}

		c.Set(UserIdKey, claims.UserID)
		c.Set(UsernameKey, claims.Username)
		c.Next()
	}
}

// RequireAdmin 检查是否为管理员
func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := GetUserID(c)
		if userID == 0 {
			response.ErrorCode(c, http.StatusUnauthorized, "未登录")
			c.Abort()
			return
		}

		// 获取用户角色
		roles, err := m.authService.roleUseCase.GetByUserID(c.Request.Context(), userID)
		if err != nil {
			response.ErrorCode(c, http.StatusInternalServerError, "获取用户角色失败")
			c.Abort()
			return
		}

		// 检查是否有admin角色
		hasAdminRole := false
		for _, role := range roles {
			if role.Code == "admin" {
				hasAdminRole = true
				break
			}
		}

		if !hasAdminRole {
			response.ErrorCode(c, http.StatusForbidden, "权限不足：此操作仅限管理员执行")
			c.Abort()
			return
		}

		c.Next()
	}
}
