<template>
  <div class="oauth-callback">
    <div class="callback-content">
      <div v-if="loading" class="loading-state">
        <el-icon class="loading-icon"><Loading /></el-icon>
        <p>正在登录中...</p>
      </div>

      <div v-else-if="needBind" class="bind-state">
        <h2>绑定账号</h2>
        <div class="oauth-info" v-if="oauthInfo">
          <img v-if="oauthInfo.avatar" :src="oauthInfo.avatar" class="oauth-avatar" />
          <div v-else class="oauth-avatar-placeholder">{{ oauthInfo.nickname?.charAt(0) || '?' }}</div>
          <p class="oauth-nickname">{{ oauthInfo.nickname }}</p>
        </div>
        <p class="bind-hint">该账号尚未绑定系统用户，请输入您的账号密码进行绑定</p>

        <el-form :model="bindForm" :rules="bindRules" ref="bindFormRef" class="bind-form">
          <el-form-item prop="username">
            <el-input v-model="bindForm.username" placeholder="请输入用户名" :prefix-icon="User" />
          </el-form-item>
          <el-form-item prop="password">
            <el-input
              v-model="bindForm.password"
              type="password"
              placeholder="请输入密码"
              show-password
              :prefix-icon="Lock"
              @keyup.enter="handleBind"
            />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="handleBind" :loading="bindLoading" class="bind-button">
              绑定并登录
            </el-button>
          </el-form-item>
        </el-form>

        <div class="back-to-login">
          <router-link to="/login">返回登录页</router-link>
        </div>
      </div>

      <div v-else-if="error" class="error-state">
        <el-icon class="error-icon"><CircleCloseFilled /></el-icon>
        <p class="error-message">{{ error }}</p>
        <el-button @click="goToLogin">返回登录</el-button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage, FormInstance } from 'element-plus'
import { Loading, CircleCloseFilled, User, Lock } from '@element-plus/icons-vue'
import { useUserStore } from '@/stores/user'
import request from '@/utils/request'

interface OAuthInfo {
  openId: string
  nickname: string
  avatar?: string
  email?: string
}

const router = useRouter()
const route = useRoute()
const userStore = useUserStore()

const loading = ref(true)
const error = ref('')
const needBind = ref(false)
const bindToken = ref('')
const oauthInfo = ref<OAuthInfo | null>(null)
const bindLoading = ref(false)
const bindFormRef = ref<FormInstance>()

const bindForm = reactive({
  username: '',
  password: ''
})

const bindRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }]
}

const goToLogin = () => {
  router.push('/login')
}

const handleCallback = async () => {
  const code = route.query.code as string
  const state = route.query.state as string
  const provider = route.params.provider as string || extractProviderFromState(state)

  if (!code || !state) {
    const errorCode = route.query.error as string
    const errorDesc = route.query.error_description as string
    if (errorCode) {
      error.value = `授权失败: ${errorCode} - ${errorDesc || ''}`
    } else {
      error.value = '缺少授权参数'
    }
    loading.value = false
    return
  }

  try {
    const res: any = await request.get(`/api/v1/public/auth/oauth/${provider}/callback`, {
      params: { code, state }
    })

    if (res.needBind) {
      // 需要绑定账号
      needBind.value = true
      bindToken.value = res.bindToken
      oauthInfo.value = res.oauthInfo
      loading.value = false
      return
    }

    // 登录成功
    if (res.token) {
      userStore.setToken(res.token)
      await userStore.fetchUserInfo()
      ElMessage.success(res.isNewUser ? '注册并登录成功' : '登录成功')
      router.push('/')
    } else {
      error.value = '登录失败，未获取到令牌'
      loading.value = false
    }
  } catch (e: any) {
    error.value = e?.message || '登录失败'
    loading.value = false
  }
}

const extractProviderFromState = (state: string): string => {
  // 尝试从state中提取provider信息（如果有的话）
  // 默认返回空字符串，实际应该由路由参数提供
  return ''
}

const handleBind = async () => {
  if (!bindFormRef.value) return

  await bindFormRef.value.validate(async (valid) => {
    if (valid) {
      bindLoading.value = true
      try {
        const provider = route.params.provider as string

        const res: any = await request.post('/api/v1/public/auth/oauth/bind', {
          provider,
          bindToken: bindToken.value,
          username: bindForm.username,
          password: bindForm.password
        })

        if (res.token) {
          userStore.setToken(res.token)
          await userStore.fetchUserInfo()
          ElMessage.success('绑定并登录成功')
          router.push('/')
        } else {
          ElMessage.error('绑定失败')
        }
      } catch (e: any) {
        ElMessage.error(e?.message || '绑定失败')
      } finally {
        bindLoading.value = false
      }
    }
  })
}

onMounted(() => {
  handleCallback()
})
</script>

<style scoped>
.oauth-callback {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #f5f5f5 0%, #e8e8e8 100%);
}

.callback-content {
  background: #fff;
  padding: 60px 50px;
  border-radius: 16px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
  text-align: center;
  max-width: 420px;
  width: 100%;
}

.loading-state {
  padding: 40px 0;
}

.loading-icon {
  font-size: 48px;
  color: #D4AF37;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.loading-state p {
  margin-top: 20px;
  font-size: 16px;
  color: #666;
}

.error-state {
  padding: 40px 0;
}

.error-icon {
  font-size: 48px;
  color: #f56c6c;
}

.error-message {
  margin: 20px 0;
  font-size: 16px;
  color: #666;
}

.bind-state h2 {
  margin-bottom: 24px;
  color: #1a1a1a;
}

.oauth-info {
  margin-bottom: 24px;
}

.oauth-avatar {
  width: 64px;
  height: 64px;
  border-radius: 50%;
  margin-bottom: 12px;
}

.oauth-avatar-placeholder {
  width: 64px;
  height: 64px;
  border-radius: 50%;
  background: linear-gradient(135deg, #D4AF37, #FFD700);
  color: #fff;
  font-size: 24px;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 12px;
}

.oauth-nickname {
  font-size: 16px;
  color: #333;
}

.bind-hint {
  font-size: 14px;
  color: #999;
  margin-bottom: 24px;
}

.bind-form {
  text-align: left;
}

.bind-form :deep(.el-form-item) {
  margin-bottom: 20px;
}

.bind-form :deep(.el-input__wrapper) {
  padding: 12px 16px;
  border-radius: 8px;
}

.bind-button {
  width: 100%;
  height: 44px;
  font-size: 16px;
  background: linear-gradient(135deg, #D4AF37 0%, #FFD700 100%);
  border: none;
}

.back-to-login {
  margin-top: 24px;
}

.back-to-login a {
  color: #666;
  font-size: 14px;
  text-decoration: none;
}

.back-to-login a:hover {
  color: #D4AF37;
}
</style>
