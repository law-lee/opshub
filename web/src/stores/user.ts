import { defineStore } from 'pinia'
import { login, register, getProfile } from '@/api/auth'
import type { LoginParams, RegisterParams } from '@/api/auth'

interface UserState {
  token: string
  userInfo: any
  avatarTimestamp: number
}

export const useUserStore = defineStore('user', {
  state: (): UserState => ({
    token: localStorage.getItem('token') || '',
    userInfo: null,
    avatarTimestamp: Date.now()
  }),

  getters: {
    isLogin: (state) => !!state.token
  },

  actions: {
    // 登录
    async login(params: LoginParams) {
      const res = await login(params)
      this.token = res.token
      this.userInfo = res.user
      localStorage.setItem('token', res.token)
      return res
    },

    // 注册
    async register(params: RegisterParams) {
      const res = await register(params)
      return res
    },

    // 获取用户信息
    async getProfile() {
      const res = await getProfile()
      this.userInfo = res
      // 更新时间戳，确保头像等资源能刷新
      this.avatarTimestamp = Date.now()
      return res
    },

    // 退出登录
    logout() {
      this.token = ''
      this.userInfo = null
      localStorage.removeItem('token')
    },

    // 更新头像
    updateAvatar(avatarUrl: string) {
      if (this.userInfo) {
        // 创建新对象以触发响应式更新
        this.userInfo = {
          ...this.userInfo,
          avatar: avatarUrl
        }
        this.avatarTimestamp = Date.now()
      }
    }
  }
})
