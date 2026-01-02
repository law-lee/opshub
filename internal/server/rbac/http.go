package rbac

import (
	"github.com/gin-gonic/gin"
	rbacService "github.com/ydcloud-dy/opshub/internal/service/rbac"
	rbacdata "github.com/ydcloud-dy/opshub/internal/data/rbac"
	rbacbiz "github.com/ydcloud-dy/opshub/internal/biz/rbac"
	"gorm.io/gorm"
)

type HTTPServer struct {
	userService       *rbacService.UserService
	roleService       *rbacService.RoleService
	departmentService *rbacService.DepartmentService
	menuService       *rbacService.MenuService
	authMiddleware    *rbacService.AuthMiddleware
}

func NewHTTPServer(
	userService *rbacService.UserService,
	roleService *rbacService.RoleService,
	departmentService *rbacService.DepartmentService,
	menuService *rbacService.MenuService,
	authMiddleware *rbacService.AuthMiddleware,
) *HTTPServer {
	return &HTTPServer{
		userService:       userService,
		roleService:       roleService,
		departmentService: departmentService,
		menuService:       menuService,
		authMiddleware:    authMiddleware,
	}
}

func (s *HTTPServer) RegisterRoutes(r *gin.Engine) {
	// 公开路由
	public := r.Group("/api/v1/public")
	{
		public.POST("/login", s.userService.Login)
	}

	// 需要认证的路由
	auth := r.Group("/api/v1")
	auth.Use(s.authMiddleware.AuthRequired())
	{
		// 用户相关
		auth.GET("/profile", s.userService.GetProfile)
		auth.PUT("/profile/password", s.userService.ChangePassword)

		// 用户管理
		users := auth.Group("/users")
		{
			users.GET("", s.userService.ListUsers)
			users.GET("/:id", s.userService.GetUser)
			users.POST("", s.userService.CreateUser)
			users.PUT("/:id", s.userService.UpdateUser)
			users.DELETE("/:id", s.userService.DeleteUser)
			users.POST("/:id/roles", s.userService.AssignUserRoles)
			users.PUT("/:id/reset-password", s.userService.ResetPassword)
		}

		// 角色管理
		roles := auth.Group("/roles")
		{
			roles.GET("", s.roleService.ListRoles)
			roles.GET("/all", s.roleService.GetAllRoles)
			roles.GET("/:id", s.roleService.GetRole)
			roles.POST("", s.roleService.CreateRole)
			roles.PUT("/:id", s.roleService.UpdateRole)
			roles.DELETE("/:id", s.roleService.DeleteRole)
			roles.POST("/:id/menus", s.roleService.AssignRoleMenus)
		}

		// 部门管理
		departments := auth.Group("/departments")
		{
			departments.GET("/tree", s.departmentService.GetDepartmentTree)
			departments.GET("/:id", s.departmentService.GetDepartment)
			departments.POST("", s.departmentService.CreateDepartment)
			departments.PUT("/:id", s.departmentService.UpdateDepartment)
			departments.DELETE("/:id", s.departmentService.DeleteDepartment)
		}

		// 菜单管理
		menus := auth.Group("/menus")
		{
			menus.GET("/tree", s.menuService.GetMenuTree)
			menus.GET("/user", s.menuService.GetUserMenu)
			menus.GET("/:id", s.menuService.GetMenu)
			menus.POST("", s.menuService.CreateMenu)
			menus.PUT("/:id", s.menuService.UpdateMenu)
			menus.DELETE("/:id", s.menuService.DeleteMenu)
		}
	}
}

// 依赖注入函数
func NewRBACServices(db *gorm.DB, jwtSecret string) (
	*rbacService.UserService,
	*rbacService.RoleService,
	*rbacService.DepartmentService,
	*rbacService.MenuService,
	*rbacService.AuthMiddleware,
) {
	// 初始化Repository
	userRepo := rbacdata.NewUserRepo(db)
	roleRepo := rbacdata.NewRoleRepo(db)
	deptRepo := rbacdata.NewDepartmentRepo(db)
	menuRepo := rbacdata.NewMenuRepo(db)

	// 初始化UseCase
	userUseCase := rbacbiz.NewUserUseCase(userRepo)
	roleUseCase := rbacbiz.NewRoleUseCase(roleRepo)
	deptUseCase := rbacbiz.NewDepartmentUseCase(deptRepo)
	menuUseCase := rbacbiz.NewMenuUseCase(menuRepo)

	// 初始化Service
	authService := rbacService.NewAuthService(jwtSecret, roleUseCase)
	userService := rbacService.NewUserService(userUseCase, authService)
	roleService := rbacService.NewRoleService(roleUseCase)
	departmentService := rbacService.NewDepartmentService(deptUseCase)
	menuService := rbacService.NewMenuService(menuUseCase)
	authMiddleware := rbacService.NewAuthMiddleware(authService)

	return userService, roleService, departmentService, menuService, authMiddleware
}
