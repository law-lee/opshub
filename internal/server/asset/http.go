package asset

import (
	"github.com/gin-gonic/gin"
	assetService "github.com/ydcloud-dy/opshub/internal/service/asset"
	assetdata "github.com/ydcloud-dy/opshub/internal/data/asset"
	assetbiz "github.com/ydcloud-dy/opshub/internal/biz/asset"
	"gorm.io/gorm"
)

type HTTPServer struct {
	assetGroupService    *assetService.AssetGroupService
	hostService          *assetService.HostService
	terminalManager      *TerminalManager
	terminalAuditHandler *TerminalAuditHandler
}

func NewHTTPServer(
	assetGroupService *assetService.AssetGroupService,
	hostService *assetService.HostService,
	terminalManager *TerminalManager,
	db *gorm.DB,
) *HTTPServer {
	return &HTTPServer{
		assetGroupService:    assetGroupService,
		hostService:          hostService,
		terminalManager:      terminalManager,
		terminalAuditHandler: NewTerminalAuditHandler(db),
	}
}

func (s *HTTPServer) RegisterRoutes(r *gin.RouterGroup) {
	// 资产分组管理
	groups := r.Group("/asset-groups")
	{
		groups.GET("/tree", s.assetGroupService.GetGroupTree)
		groups.GET("/parent-options", s.assetGroupService.GetParentOptions)
		groups.POST("", s.assetGroupService.CreateGroup)
		groups.GET("/:id", s.assetGroupService.GetGroup)
		groups.PUT("/:id", s.assetGroupService.UpdateGroup)
		groups.DELETE("/:id", s.assetGroupService.DeleteGroup)
	}

	// 主机管理
	hosts := r.Group("/hosts")
	{
		hosts.GET("", s.hostService.ListHosts)
		hosts.GET("/template/download", s.hostService.DownloadExcelTemplate)
		hosts.POST("/import", s.hostService.ImportFromExcel)
		hosts.POST("/batch-collect", s.hostService.BatchCollectHostInfo)
		hosts.POST("/batch-delete", s.hostService.BatchDeleteHosts)
		hosts.GET("/:id", s.hostService.GetHost)
		hosts.POST("", s.hostService.CreateHost)
		hosts.PUT("/:id", s.hostService.UpdateHost)
		hosts.DELETE("/:id", s.hostService.DeleteHost)
		hosts.POST("/:id/collect", s.hostService.CollectHostInfo)
		hosts.POST("/:id/test", s.hostService.TestHostConnection)
		// 文件管理
		hosts.GET("/:id/files", s.hostService.ListHostFiles)
		hosts.POST("/:id/files/upload", s.hostService.UploadHostFile)
		hosts.GET("/:id/files/download", s.hostService.DownloadHostFile)
		hosts.DELETE("/:id/files", s.hostService.DeleteHostFile)
	}

	// 凭证管理
	credentials := r.Group("/credentials")
	{
		credentials.GET("", s.hostService.ListCredentials)
		credentials.GET("/all", s.hostService.GetAllCredentials)
		credentials.GET("/:id", s.hostService.GetCredential)
		credentials.POST("", s.hostService.CreateCredential)
		credentials.PUT("/:id", s.hostService.UpdateCredential)
		credentials.DELETE("/:id", s.hostService.DeleteCredential)
	}

	// 云平台账号管理
	cloudAccounts := r.Group("/cloud-accounts")
	{
		cloudAccounts.GET("", s.hostService.ListCloudAccounts)
		cloudAccounts.GET("/all", s.hostService.GetAllCloudAccounts)
		cloudAccounts.GET("/:id", s.hostService.GetCloudAccount)
		cloudAccounts.GET("/:id/regions", s.hostService.GetCloudRegions)
		cloudAccounts.GET("/:id/instances", s.hostService.GetCloudInstances)
		cloudAccounts.POST("", s.hostService.CreateCloudAccount)
		cloudAccounts.PUT("/:id", s.hostService.UpdateCloudAccount)
		cloudAccounts.DELETE("/:id", s.hostService.DeleteCloudAccount)
		cloudAccounts.POST("/import", s.hostService.ImportFromCloud)
	}

	// SSH终端
	terminal := r.Group("/asset/terminal")
	{
		terminal.GET("/:id", s.HandleSSHConnection)
		terminal.POST("/:id/resize", s.ResizeTerminal)
	}

	// 终端审计
	terminalSessions := r.Group("/terminal-sessions")
	{
		terminalSessions.GET("", s.terminalAuditHandler.ListTerminalSessions)
		terminalSessions.GET("/:id/play", s.terminalAuditHandler.PlayTerminalSession)
		terminalSessions.DELETE("/:id", s.terminalAuditHandler.DeleteTerminalSession)
	}
}

// NewAssetServices 创建asset相关的服务
func NewAssetServices(db *gorm.DB) (
	*assetService.AssetGroupService,
	*assetService.HostService,
	*TerminalManager,
) {
	// 初始化Repository
	assetGroupRepo := assetdata.NewAssetGroupRepo(db)
	hostRepo := assetdata.NewHostRepo(db)
	credentialRepo := assetdata.NewCredentialRepo(db)
	cloudAccountRepo := assetdata.NewCloudAccountRepo(db)

	// 初始化UseCase
	assetGroupUseCase := assetbiz.NewAssetGroupUseCase(assetGroupRepo)
	credentialUseCase := assetbiz.NewCredentialUseCase(credentialRepo, hostRepo)
	cloudAccountUseCase := assetbiz.NewCloudAccountUseCase(cloudAccountRepo)
	hostUseCase := assetbiz.NewHostUseCase(hostRepo, credentialRepo, assetGroupRepo, cloudAccountRepo)

	// 初始化Service
	assetGroupService := assetService.NewAssetGroupService(assetGroupUseCase)
	hostService := assetService.NewHostService(hostUseCase, credentialUseCase, cloudAccountUseCase)

	// 初始化TerminalManager
	terminalManager := NewTerminalManager(hostUseCase, db)

	return assetGroupService, hostService, terminalManager
}
