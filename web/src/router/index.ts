import { createRouter, createWebHistory } from 'vue-router'
import { useUserStore } from '@/stores/user'
import { pluginManager } from '@/plugins/manager'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('@/views/Login.vue'),
      meta: { title: '登录' }
    },
    {
      path: '/',
      name: 'Layout',
      component: () => import('@/views/Layout.vue'),
      redirect: '/dashboard',
      children: [
        {
          path: 'dashboard',
          name: 'Dashboard',
          component: () => import('@/views/Dashboard.vue'),
          meta: { title: '首页' }
        },
        {
          path: 'users',
          name: 'Users',
          component: () => import('@/views/system/Users.vue'),
          meta: { title: '用户管理' }
        },
        {
          path: 'roles',
          name: 'Roles',
          component: () => import('@/views/system/Roles.vue'),
          meta: { title: '角色管理' }
        },
        {
          path: 'departments',
          name: 'Departments',
          component: () => import('@/views/system/Departments.vue'),
          meta: { title: '部门管理' }
        },
        {
          path: 'menus',
          name: 'Menus',
          component: () => import('@/views/system/Menus.vue'),
          meta: { title: '菜单管理' }
        },
        {
          path: 'profile',
          name: 'Profile',
          component: () => import('@/views/Profile.vue'),
          meta: { title: '个人信息' }
        }
      ]
    }
  ]
})

// 注册插件路由
export function registerPluginRoutes() {
  // 修改为使用 getInstalled() 以保持与菜单构建的一致性
  const plugins = pluginManager.getInstalled()

  console.log('[Router] 开始注册插件路由')
  console.log('[Router] 已安装的插件数量:', plugins.length)

  for (const plugin of plugins) {
    if (plugin.getRoutes) {
      const routes = plugin.getRoutes()

      // 添加插件的子路由到 Layout
      routes.forEach(route => {
        router.addRoute('Layout', route)
      })

      console.log(`[Router] 插件 ${plugin.name} 路由注册成功, 路由数量:`, routes.length)
    } else {
      console.log(`[Router] 插件 ${plugin.name} 没有提供路由配置`)
    }
  }

  console.log('[Router] 插件路由注册完成')
}

// 路由守卫
router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('token')
  console.log('路由守卫 - 目标路径:', to.path)
  console.log('路由守卫 - 当前路径:', from.path)
  console.log('路由守卫 - Token:', token)

  // 如果访问登录页，且已登录，则跳转到首页
  if (to.path === '/login') {
    if (token) {
      console.log('已登录访问登录页，跳转到首页')
      next('/')
    } else {
      console.log('未登录访问登录页，继续')
      next()
    }
  } else {
    // 访问其他页面，需要检查登录状态
    if (!token) {
      console.log('未登录，跳转到登录页')
      next('/login')
    } else {
      console.log('已登录，继续访问')
      next()
    }
  }
})

export default router

