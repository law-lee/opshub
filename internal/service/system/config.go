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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ydcloud-dy/opshub/internal/biz/system"
	"github.com/ydcloud-dy/opshub/pkg/response"
)

// ConfigService 系统配置服务
type ConfigService struct {
	configUseCase *system.ConfigUseCase
	uploadDir     string
}

// NewConfigService 创建系统配置服务
func NewConfigService(configUseCase *system.ConfigUseCase, uploadDir string) *ConfigService {
	return &ConfigService{
		configUseCase: configUseCase,
		uploadDir:     uploadDir,
	}
}

// GetAllConfig 获取所有配置
// @Summary 获取所有系统配置
// @Description 获取基础配置和安全配置
// @Tags 系统配置
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} response.Response{} "获取成功"
// @Router /api/v1/system/config [get]
func (s *ConfigService) GetAllConfig(c *gin.Context) {
	config, err := s.configUseCase.GetAllConfig(c.Request.Context())
	if err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "获取配置失败: "+err.Error())
		return
	}
	response.Success(c, config)
}

// GetBasicConfig 获取基础配置
// @Summary 获取基础配置
// @Description 获取系统名称、Logo、描述等基础配置
// @Tags 系统配置
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} response.Response{} "获取成功"
// @Router /api/v1/system/config/basic [get]
func (s *ConfigService) GetBasicConfig(c *gin.Context) {
	config, err := s.configUseCase.GetBasicConfig(c.Request.Context())
	if err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "获取配置失败: "+err.Error())
		return
	}
	response.Success(c, config)
}

// SaveBasicConfigRequest 保存基础配置请求
type SaveBasicConfigRequest struct {
	SystemName        string `json:"systemName"`
	SystemLogo        string `json:"systemLogo"`
	SystemDescription string `json:"systemDescription"`
}

// SaveBasicConfig 保存基础配置
// @Summary 保存基础配置
// @Description 保存系统名称、Logo、描述等基础配置
// @Tags 系统配置
// @Accept json
// @Produce json
// @Security Bearer
// @Param body body SaveBasicConfigRequest true "基础配置"
// @Success 200 {object} response.Response "保存成功"
// @Router /api/v1/system/config/basic [put]
func (s *ConfigService) SaveBasicConfig(c *gin.Context) {
	var req SaveBasicConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorCode(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}

	config := &system.BasicConfig{
		SystemName:        req.SystemName,
		SystemLogo:        req.SystemLogo,
		SystemDescription: req.SystemDescription,
	}

	if err := s.configUseCase.SaveBasicConfig(c.Request.Context(), config); err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	response.SuccessWithMessage(c, "保存成功", nil)
}

// GetSecurityConfig 获取安全配置
// @Summary 获取安全配置
// @Description 获取密码策略、登录安全等配置
// @Tags 系统配置
// @Accept json
// @Produce json
// @Security Bearer
// @Success 200 {object} response.Response{} "获取成功"
// @Router /api/v1/system/config/security [get]
func (s *ConfigService) GetSecurityConfig(c *gin.Context) {
	config, err := s.configUseCase.GetSecurityConfig(c.Request.Context())
	if err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "获取配置失败: "+err.Error())
		return
	}
	response.Success(c, config)
}

// SaveSecurityConfigRequest 保存安全配置请求
type SaveSecurityConfigRequest struct {
	PasswordMinLength int  `json:"passwordMinLength"`
	SessionTimeout    int  `json:"sessionTimeout"`
	EnableCaptcha     bool `json:"enableCaptcha"`
	MaxLoginAttempts  int  `json:"maxLoginAttempts"`
	LockoutDuration   int  `json:"lockoutDuration"`
}

// SaveSecurityConfig 保存安全配置
// @Summary 保存安全配置
// @Description 保存密码策略、登录安全等配置
// @Tags 系统配置
// @Accept json
// @Produce json
// @Security Bearer
// @Param body body SaveSecurityConfigRequest true "安全配置"
// @Success 200 {object} response.Response "保存成功"
// @Router /api/v1/system/config/security [put]
func (s *ConfigService) SaveSecurityConfig(c *gin.Context) {
	var req SaveSecurityConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ErrorCode(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}

	// 验证参数
	if req.PasswordMinLength < 6 || req.PasswordMinLength > 20 {
		response.ErrorCode(c, http.StatusBadRequest, "密码最小长度必须在6-20之间")
		return
	}
	if req.MaxLoginAttempts < 3 || req.MaxLoginAttempts > 10 {
		response.ErrorCode(c, http.StatusBadRequest, "最大登录失败次数必须在3-10之间")
		return
	}

	config := &system.SecurityConfig{
		PasswordMinLength: req.PasswordMinLength,
		SessionTimeout:    req.SessionTimeout,
		EnableCaptcha:     req.EnableCaptcha,
		MaxLoginAttempts:  req.MaxLoginAttempts,
		LockoutDuration:   req.LockoutDuration,
	}

	if err := s.configUseCase.SaveSecurityConfig(c.Request.Context(), config); err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	response.SuccessWithMessage(c, "保存成功", nil)
}

// UploadLogo 上传系统Logo
// @Summary 上传系统Logo
// @Description 上传系统Logo图片
// @Tags 系统配置
// @Accept multipart/form-data
// @Produce json
// @Security Bearer
// @Param file formance file true "Logo图片文件"
// @Success 200 {object} response.Response{} "上传成功"
// @Router /api/v1/system/config/logo [post]
func (s *ConfigService) UploadLogo(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		response.ErrorCode(c, http.StatusBadRequest, "获取文件失败: "+err.Error())
		return
	}
	defer file.Close()

	// 验证文件类型
	ext := strings.ToLower(filepath.Ext(header.Filename))
	allowedExts := map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".ico": true, ".svg": true}
	if !allowedExts[ext] {
		response.ErrorCode(c, http.StatusBadRequest, "不支持的文件格式，仅支持 png/jpg/jpeg/ico/svg")
		return
	}

	// 验证文件大小 (最大2MB)
	if header.Size > 2*1024*1024 {
		response.ErrorCode(c, http.StatusBadRequest, "文件大小不能超过2MB")
		return
	}

	// 创建目录
	logoDir := filepath.Join(s.uploadDir, "logo")
	if err := os.MkdirAll(logoDir, 0755); err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "创建目录失败")
		return
	}

	// 生成文件名
	filename := fmt.Sprintf("logo_%d%s", time.Now().UnixNano(), ext)
	filePath := filepath.Join(logoDir, filename)

	// 保存文件
	dst, err := os.Create(filePath)
	if err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "创建文件失败")
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		response.ErrorCode(c, http.StatusInternalServerError, "保存文件失败")
		return
	}

	// 返回文件路径
	logoURL := "/uploads/logo/" + filename

	// 保存到配置
	basicConfig := &system.BasicConfig{
		SystemLogo: logoURL,
	}
	// 只更新Logo字段
	if err := s.configUseCase.SaveBasicConfig(c.Request.Context(), basicConfig); err != nil {
		// 忽略错误，文件已经上传成功
	}

	response.Success(c, gin.H{
		"url": logoURL,
	})
}

// GetPublicConfig 获取公开配置（无需认证）
// @Summary 获取公开配置
// @Description 获取登录页面需要的配置（验证码开关等）
// @Tags 系统配置
// @Accept json
// @Produce json
// @Success 200 {object} response.Response{} "获取成功"
// @Router /api/v1/public/config [get]
func (s *ConfigService) GetPublicConfig(c *gin.Context) {
	// 获取基础配置
	basicConfig, _ := s.configUseCase.GetBasicConfig(c.Request.Context())
	if basicConfig == nil {
		basicConfig = &system.BasicConfig{
			SystemName:        "OpsHub",
			SystemLogo:        "",
			SystemDescription: "运维管理平台",
		}
	}

	// 获取安全配置
	securityConfig, _ := s.configUseCase.GetSecurityConfig(c.Request.Context())
	if securityConfig == nil {
		securityConfig = &system.SecurityConfig{
			EnableCaptcha: true,
		}
	}

	response.Success(c, gin.H{
		"systemName":        basicConfig.SystemName,
		"systemLogo":        basicConfig.SystemLogo,
		"systemDescription": basicConfig.SystemDescription,
		"enableCaptcha":     securityConfig.EnableCaptcha,
	})
}

// GetConfigUseCase 获取配置用例（供其他服务使用）
func (s *ConfigService) GetConfigUseCase() *system.ConfigUseCase {
	return s.configUseCase
}
