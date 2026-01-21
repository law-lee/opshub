package server

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ydcloud-dy/opshub/internal/biz/rbac"
	rbaccustom "github.com/ydcloud-dy/opshub/internal/service/rbac"
	appLogger "github.com/ydcloud-dy/opshub/pkg/logger"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// UploadServer 上传服务
type UploadServer struct {
	db        *gorm.DB
	uploadDir string
	uploadURL string
}

// NewUploadServer 创建上传服务
func NewUploadServer(db *gorm.DB, uploadDir, uploadURL string) *UploadServer {
	// 确保上传目录存在
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		appLogger.Error("创建上传目录失败", zap.Error(err))
	}

	return &UploadServer{
		db:        db,
		uploadDir: uploadDir,
		uploadURL: uploadURL,
	}
}

// UploadAvatar 上传头像
func (s *UploadServer) UploadAvatar(c *gin.Context) {
	// 获取上传的文件
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "获取文件失败",
		})
		return
	}
	defer file.Close()

	// 验证文件类型
	if !strings.HasPrefix(header.Header.Get("Content-Type"), "image/") {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "只能上传图片文件",
		})
		return
	}

	// 验证文件大小 (2MB)
	if header.Size > 2*1024*1024 {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "图片大小不能超过 2MB",
		})
		return
	}

	// 获取当前用户ID (从JWT中获取)
	userID := rbaccustom.GetUserID(c)
	if userID == 0 {
		c.JSON(401, gin.H{
			"code":    401,
			"message": "未登录",
		})
		return
	}

	// 生成唯一文件名
	ext := filepath.Ext(header.Filename)
	filename := fmt.Sprintf("avatar_%d_%d%s", userID, time.Now().Unix(), ext)

	// 保存文件
	dst := filepath.Join(s.uploadDir, filename)
	out, err := os.Create(dst)
	if err != nil {
		appLogger.Error("创建文件失败", zap.Error(err))
		c.JSON(500, gin.H{
			"code":    500,
			"message": "保存文件失败",
		})
		return
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		appLogger.Error("写入文件失败", zap.Error(err))
		c.JSON(500, gin.H{
			"code":    500,
			"message": "保存文件失败",
		})
		return
	}

	// 生成访问URL
	fileURL := fmt.Sprintf("%s/%s", s.uploadURL, filename)

	appLogger.Info("头像上传成功",
		zap.Uint("userID", userID),
		zap.String("filename", filename),
		zap.String("url", fileURL),
	)

	c.JSON(200, gin.H{
		"code":    0,
		"message": "success",
		"data": gin.H{
			"url":  fileURL,
			"path": filename,
		},
	})
}

// UpdateUserAvatar 更新用户头像
func (s *UploadServer) UpdateUserAvatar(c *gin.Context) {
	var req struct {
		Avatar string `json:"avatar" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "参数错误",
		})
		return
	}

	// 获取当前用户ID
	userID := rbaccustom.GetUserID(c)
	if userID == 0 {
		c.JSON(401, gin.H{
			"code":    401,
			"message": "未登录",
		})
		return
	}

	// 更新用户头像
	if err := s.db.Model(&rbac.SysUser{}).Where("id = ?", userID).Update("avatar", req.Avatar).Error; err != nil {
		appLogger.Error("更新头像失败",
			zap.Uint("userID", userID),
			zap.Error(err),
		)
		c.JSON(500, gin.H{
			"code":    500,
			"message": "更新头像失败",
		})
		return
	}

	appLogger.Info("用户头像更新成功",
		zap.Uint("userID", userID),
		zap.String("avatar", req.Avatar),
	)

	c.JSON(200, gin.H{
		"code":    0,
		"message": "头像更新成功",
	})
}

// UploadPlugin 上传并安装插件
func (s *UploadServer) UploadPlugin(c *gin.Context) {
	// 获取上传的文件
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "获取文件失败",
		})
		return
	}
	defer file.Close()

	// 验证文件类型
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "只能上传 .zip 格式的插件包",
		})
		return
	}

	// 验证文件大小 (50MB)
	if header.Size > 50*1024*1024 {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "插件包大小不能超过 50MB",
		})
		return
	}

	// 创建临时文件保存上传的zip
	tempDir := os.TempDir()
	timestamp := time.Now().Unix()
	zipPath := filepath.Join(tempDir, fmt.Sprintf("plugin_%d.zip", timestamp))

	// 保存上传的文件
	out, err := os.Create(zipPath)
	if err != nil {
		appLogger.Error("创建临时文件失败", zap.Error(err))
		c.JSON(500, gin.H{
			"code":    500,
			"message": "保存文件失败",
		})
		return
	}

	_, err = io.Copy(out, file)
	out.Close()
	if err != nil {
		appLogger.Error("写入文件失败", zap.Error(err))
		os.Remove(zipPath)
		c.JSON(500, gin.H{
			"code":    500,
			"message": "保存文件失败",
		})
		return
	}

	// 延迟清理临时文件
	defer os.Remove(zipPath)

	// 解压插件
	if err := s.extractPlugin(zipPath); err != nil {
		appLogger.Error("解压插件失败", zap.Error(err))
		c.JSON(500, gin.H{
			"code":    500,
			"message": fmt.Sprintf("解压插件失败: %v", err),
		})
		return
	}

	appLogger.Info("插件上传并安装成功",
		zap.String("filename", header.Filename),
		zap.Int64("size", header.Size),
	)

	c.JSON(200, gin.H{
		"code":    0,
		"message": "插件安装成功，请重启服务使插件生效",
	})
}

// extractPlugin 解压插件包
func (s *UploadServer) extractPlugin(zipPath string) error {
	// 打开zip文件
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("打开zip文件失败: %w", err)
	}
	defer r.Close()

	// 获取项目根目录
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("获取当前目录失败: %w", err)
	}

	// 遍历zip中的文件
	for _, f := range r.File {
		// 跳过 __MACOSX 等系统文件
		if strings.Contains(f.Name, "__MACOSX") || strings.Contains(f.Name, ".DS_Store") {
			continue
		}

		// 去掉顶层目录（如 test-plugin/），只保留 web/ 或 backend/ 开头的路径
		parts := strings.Split(f.Name, "/")
		if len(parts) < 2 {
			continue
		}

		// 重新组合路径，去掉第一层目录
		relativePath := strings.Join(parts[1:], "/")
		if relativePath == "" {
			continue
		}

		var targetPath string
		if strings.HasPrefix(relativePath, "web/") {
			// 前端插件
			targetPath = filepath.Join(currentDir, relativePath)
		} else if strings.HasPrefix(relativePath, "backend/") {
			// 后端插件，将 backend/ 映射到 plugins/
			pluginPath := strings.TrimPrefix(relativePath, "backend/")
			targetPath = filepath.Join(currentDir, "plugins", pluginPath)
		} else {
			// 跳过不符合格式的文件
			continue
		}

		// 如果是目录，创建目录
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, os.ModePerm); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}
			continue
		}

		// 确保父目录存在
		if err := os.MkdirAll(filepath.Dir(targetPath), os.ModePerm); err != nil {
			return fmt.Errorf("创建父目录失败: %w", err)
		}

		// 提取文件
		if err := s.extractFile(f, targetPath); err != nil {
			return fmt.Errorf("提取文件 %s 失败: %w", f.Name, err)
		}

		appLogger.Info("文件提取成功",
			zap.String("source", f.Name),
			zap.String("target", targetPath),
		)
	}

	return nil
}

// UninstallPlugin 卸载插件
func (s *UploadServer) UninstallPlugin(c *gin.Context) {
	pluginName := c.Param("name")
	if pluginName == "" {
		c.JSON(400, gin.H{
			"code":    400,
			"message": "插件名称不能为空",
		})
		return
	}

	// 获取项目根目录
	currentDir, err := os.Getwd()
	if err != nil {
		appLogger.Error("获取当前目录失败", zap.Error(err))
		c.JSON(500, gin.H{
			"code":    500,
			"message": "获取当前目录失败",
		})
		return
	}

	// 删除前端插件目录
	webPluginDir := filepath.Join(currentDir, "web", "src", "plugins", pluginName)
	if err := os.RemoveAll(webPluginDir); err != nil {
		appLogger.Error("删除前端插件目录失败",
			zap.String("plugin", pluginName),
			zap.String("path", webPluginDir),
			zap.Error(err),
		)
		// 继续执行，不中断
	} else {
		appLogger.Info("前端插件目录删除成功",
			zap.String("plugin", pluginName),
			zap.String("path", webPluginDir),
		)
	}

	// 删除后端插件目录
	backendPluginDir := filepath.Join(currentDir, "plugins", pluginName)
	if err := os.RemoveAll(backendPluginDir); err != nil {
		appLogger.Error("删除后端插件目录失败",
			zap.String("plugin", pluginName),
			zap.String("path", backendPluginDir),
			zap.Error(err),
		)
		// 继续执行，不中断
	} else {
		appLogger.Info("后端插件目录删除成功",
			zap.String("plugin", pluginName),
			zap.String("path", backendPluginDir),
		)
	}

	// 从数据库中删除插件状态
	if err := s.db.Exec("DELETE FROM plugin_states WHERE name = ?", pluginName).Error; err != nil {
		appLogger.Error("删除插件状态失败",
			zap.String("plugin", pluginName),
			zap.Error(err),
		)
	} else {
		appLogger.Info("插件状态删除成功", zap.String("plugin", pluginName))
	}

	appLogger.Info("插件卸载成功", zap.String("plugin", pluginName))

	c.JSON(200, gin.H{
		"code":    0,
		"message": "插件卸载成功，请刷新页面并重启服务以生效",
	})
}

// extractFile 提取单个文件
func (s *UploadServer) extractFile(f *zip.File, targetPath string) error {
	// 打开zip中的文件
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	// 创建目标文件
	outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer outFile.Close()

	// 复制内容
	_, err = io.Copy(outFile, rc)
	return err
}
