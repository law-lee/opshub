<template>
  <div class="clusters-container">
    <!-- 页面标题和操作按钮 -->
    <div class="page-header">
      <h2 class="page-title">集群管理</h2>
      <el-button class="black-button" @click="handleRegister">
        <el-icon style="margin-right: 4px;"><Plus /></el-icon>
        注册集群
      </el-button>
    </div>

    <!-- 搜索和筛选 -->
    <div class="search-bar">
      <el-form :inline="true" :model="searchForm">
        <el-form-item>
          <el-input
            v-model="searchForm.keyword"
            placeholder="搜索集群名称或别名"
            clearable
            @clear="handleSearch"
            @keyup.enter="handleSearch"
            style="width: 240px"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
            <template #append>
              <el-button :icon="Search" @click="handleSearch" />
            </template>
          </el-input>
        </el-form-item>

        <el-form-item>
          <el-select
            v-model="searchForm.status"
            placeholder="集群状态"
            clearable
            @change="handleSearch"
            style="width: 140px"
          >
            <el-option label="正常" :value="1" />
            <el-option label="连接失败" :value="2" />
            <el-option label="不可用" :value="3" />
          </el-select>
        </el-form-item>

        <el-form-item>
          <el-input
            v-model="searchForm.version"
            placeholder="集群版本"
            clearable
            @clear="handleSearch"
            @keyup.enter="handleSearch"
            style="width: 160px"
          >
            <template #prefix>
              <el-icon color="#67C23A"><InfoFilled /></el-icon>
            </template>
          </el-input>
        </el-form-item>

        <el-form-item>
          <el-button @click="handleReset">
            <el-icon style="margin-right: 4px;"><RefreshLeft /></el-icon>
            重置
          </el-button>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="handleSearch">
            <el-icon style="margin-right: 4px;"><Search /></el-icon>
            搜索
          </el-button>
        </el-form-item>
      </el-form>
    </div>

    <!-- 集群列表 -->
    <el-table :data="filteredClusterList" border stripe v-loading="loading" style="width: 100%">
      <el-table-column prop="name" label="集群名称" min-width="200">
        <template #default="{ row }">
          <span
            class="cluster-name-link"
            @click="handleViewDetail(row)"
            style="display: flex; align-items: center; gap: 6px; cursor: pointer;"
          >
            <el-icon color="#409EFF" :size="18"><Platform /></el-icon>
            {{ row.name }}
          </span>
        </template>
      </el-table-column>
      <el-table-column prop="alias" label="别名" width="150" />
      <el-table-column prop="version" label="版本" width="180">
        <template #default="{ row }">
          <span style="display: flex; align-items: center; gap: 6px;">
            <el-icon color="#67C23A" :size="18"><InfoFilled /></el-icon>
            {{ row.version }}
          </span>
        </template>
      </el-table-column>
      <el-table-column prop="nodeCount" label="节点数" width="120" align="center">
        <template #default="{ row }">
          <el-tag type="info">{{ row.nodeCount }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="120" align="center">
        <template #default="{ row }">
          <el-tag :type="getStatusType(row.status)">
            {{ getStatusText(row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="集群凭证" width="120" align="center">
        <template #default="{ row }">
          <el-button
            link
            type="primary"
            @click="handleViewConfig(row)"
            title="查看集群凭证"
          >
            <el-icon size="20"><Key /></el-icon>
          </el-button>
        </template>
      </el-table-column>
      <el-table-column prop="description" label="备注" min-width="180" show-overflow-tooltip />
      <el-table-column prop="createdAt" label="创建时间" width="200" />
      <el-table-column label="操作" width="140" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="handleSync(row)" title="同步">
            <el-icon size="18"><Refresh /></el-icon>
          </el-button>
          <el-button link type="primary" @click="handleEdit(row)" title="编辑">
            <el-icon size="18"><Edit /></el-icon>
          </el-button>
          <el-button link type="danger" @click="handleDelete(row)" title="删除">
            <el-icon size="18"><Delete /></el-icon>
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 注册/编辑集群对话框 -->
    <el-dialog
      v-model="dialogVisible"
      :title="isEdit ? '编辑集群' : '注册集群'"
      width="700px"
      @close="handleDialogClose"
      class="cluster-dialog"
    >
      <el-form :model="clusterForm" :rules="rules" ref="formRef" label-width="100px">
        <!-- 基本信息 -->
        <div class="form-section">
          <div class="section-title">基本信息</div>
          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="集群名称" prop="name">
                <el-input v-model="clusterForm.name" placeholder="请输入集群名称"  />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="集群别名">
                <el-input v-model="clusterForm.alias" placeholder="可选" />
              </el-form-item>
            </el-col>
          </el-row>
        </div>

        <!-- 认证配置 -->
        <div class="form-section">
          <div class="section-title">认证配置</div>
          <el-form-item label="认证方式">
            <el-radio-group v-model="authType" @change="handleAuthTypeChange" size="large" >
              <el-radio-button label="config">KubeConfig 文件</el-radio-button>
              <el-radio-button label="token">Service Account Token</el-radio-button>
            </el-radio-group>
          </el-form-item>

          <!-- KubeConfig 方式 -->
          <template v-if="authType === 'config'">
            <el-alert
              v-if="isEdit"
              title="配置信息"
              type="info"
              :closable="false"
              style="margin-bottom: 12px"
            >
              <template #default>
                <div style="font-size: 12px;">
                  <p style="margin: 0 0 8px 0;">
                    <strong>当前集群配置信息：</strong>
                  </p>
                  <ul style="margin: 0; padding-left: 20px;">
                    <li>API Endpoint: {{ clusterForm.apiEndpoint || '未配置' }}</li>
                    <li>服务商: {{ clusterForm.provider ? getProviderText(clusterForm.provider) : '未配置' }}</li>
                    <li>区域: {{ clusterForm.region || '未配置' }}</li>
                  </ul>
                  <p style="margin: 8px 0 0 0; color: #409eff;">
                    💡 如需更新集群凭证，请在下方重新输入新的 KubeConfig；留空则保持原配置不变
                  </p>
                </div>
              </template>
            </el-alert>
            <el-form-item label="配置内容" prop="kubeConfig">
              <div style="margin-bottom: 8px;">
                <el-button size="small" @click="handleUploadKubeConfig">
                  <el-icon><Upload /></el-icon>
                  上传 KubeConfig 文件
                </el-button>
                <input
                  ref="fileInputRef"
                  type="file"
                  accept=".conf,.yaml,.yml,.json"
                  style="display: none"
                  @change="handleFileChange"
                />
              </div>
              <div class="code-editor-wrapper">
                <div class="line-numbers">
                  <div v-for="n in lineCount" :key="n" class="line-number">{{ n }}</div>
                </div>
                <textarea
                  v-model="clusterForm.kubeConfig"
                  class="code-textarea"
                  :placeholder="isEdit ? '' : '请粘贴 KubeConfig 文件内容或点击上方按钮上传'"
                  spellcheck="false"
                  @input="updateLineCount"

                ></textarea>
              </div>
              <div class="code-tip" v-if="!isEdit">
                <el-icon><InfoFilled /></el-icon>
                <span>如何获取 KubeConfig？通常位于 ~/.kube/config 文件中</span>
              </div>
            </el-form-item>
          </template>

          <!-- Token 方式 -->
          <template v-if="authType === 'token'">
            <el-form-item label="API 地址" prop="apiEndpoint">
              <el-input
                v-model="clusterForm.apiEndpoint"
                placeholder="https://k8s-api.example.com:6443"
                
              >
                <template #prepend>
                  <el-icon><Connection /></el-icon>
                </template>
              </el-input>
            </el-form-item>
            <el-form-item label="Token" prop="token">
              <div class="code-editor-wrapper">
                <div class="line-numbers">
                  <div v-for="n in tokenLineCount" :key="n" class="line-number">{{ n }}</div>
                </div>
                <textarea
                  v-model="clusterForm.token"
                  class="code-textarea"
                  placeholder="请输入 Service Account Token"
                  spellcheck="false"
                  @input="updateTokenLineCount"
                  
                ></textarea>
              </div>
              <div class="code-tip">
                <el-icon><InfoFilled /></el-icon>
                <span>如何获取 Token？使用 kubectl create token 命令创建</span>
              </div>
            </el-form-item>
          </template>
        </div>

        <!-- 集群信息 -->
        <div class="form-section">
          <div class="section-title">集群信息</div>
          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="服务商">
                <el-select v-model="clusterForm.provider" placeholder="请选择" style="width: 100%">
                  <el-option label="自建集群" value="native" />
                  <el-option label="阿里云 ACK" value="aliyun" />
                  <el-option label="腾讯云 TKE" value="tencent" />
                  <el-option label="AWS EKS" value="aws" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="区域">
                <el-input v-model="clusterForm.region" placeholder="例如: cn-beijing" />
              </el-form-item>
            </el-col>
          </el-row>
          <el-form-item label="备注">
            <el-input
              v-model="clusterForm.description"
              type="textarea"
              :rows="2"
              placeholder="请输入集群备注（可选）"
            />
          </el-form-item>
        </div>
      </el-form>

      <template #footer>
        <div class="dialog-footer">
          <el-button @click="dialogVisible = false" size="large">取消</el-button>
          <el-button class="black-button" @click="handleSubmit" :loading="submitLoading" size="large">
            {{ isEdit ? '保存' : '注册集群' }}
          </el-button>
        </div>
      </template>
    </el-dialog>

    <!-- 查看集群凭证对话框 -->
    <el-dialog
      v-model="configDialogVisible"
      title="集群凭证"
      width="700px"
      class="config-dialog"
    >
      <div style="margin-bottom: 16px;">
        <el-descriptions :column="2" border size="default" :label-style="{ width: '100px', fontSize: '14px' }" :content-style="{ fontSize: '14px' }">
          <el-descriptions-item label="集群名称">{{ currentCluster?.name }}</el-descriptions-item>
          <el-descriptions-item label="别名">{{ currentCluster?.alias || '-' }}</el-descriptions-item>
          <el-descriptions-item label="API Endpoint">{{ currentCluster?.apiEndpoint }}</el-descriptions-item>
          <el-descriptions-item label="版本">{{ currentCluster?.version }}</el-descriptions-item>
        </el-descriptions>
      </div>

      <div style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
        <span style="font-weight: 500; color: #303133; font-size: 14px;">KubeConfig 配置</span>
        <div>
          <el-button size="small" @click="handleCopyConfig">
            <el-icon><DocumentCopy /></el-icon>
            复制
          </el-button>
          <el-button size="small" @click="handleDownloadConfig">
            <el-icon><Download /></el-icon>
            下载
          </el-button>
        </div>
      </div>

      <div class="code-editor-wrapper">
        <div class="line-numbers">
          <div v-for="n in configLineCount" :key="n" class="line-number">{{ n }}</div>
        </div>
        <textarea
          v-model="currentConfig"
          class="code-textarea"
          readonly
          spellcheck="false"
          style="font-size: 13px;"
        ></textarea>
      </div>

      <div class="code-tip" style="font-size: 13px;">
        <el-icon><Warning /></el-icon>
        <span>请妥善保管集群凭证，不要泄露给他人</span>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox, FormInstance } from 'element-plus'
import {
  Search,
  InfoFilled,
  Connection,
  Upload,
  Platform,
  Key,
  Refresh,
  RefreshLeft,
  Plus,
  Edit,
  Delete,
  DocumentCopy,
  Download,
  Warning
} from '@element-plus/icons-vue'
import {
  getClusterList,
  createCluster,
  updateCluster,
  deleteCluster,
  testClusterConnection,
  getClusterDetail,
  getClusterConfig,
  type Cluster
} from '@/api/kubernetes'

const loading = ref(false)
const dialogVisible = ref(false)
const configDialogVisible = ref(false)
const submitLoading = ref(false)
const formRef = ref<FormInstance>()
const fileInputRef = ref<HTMLInputElement>()
const authType = ref('config')
const lineCount = ref(1)
const tokenLineCount = ref(1)
const isEdit = ref(false)
const editClusterId = ref<number>()
const kubeConfigEditable = ref(false)
const currentCluster = ref<Cluster>()
const currentConfig = ref('')
const configLineCount = ref(1)
const router = useRouter()

const clusterList = ref<Cluster[]>([])

// 搜索表单
const searchForm = reactive({
  keyword: '',
  status: undefined as number | undefined,
  version: ''
})

const clusterForm = reactive({
  name: '',
  alias: '',
  apiEndpoint: '',
  kubeConfig: '',
  token: '',
  provider: 'native',
  region: '',
  description: ''
})

const rules = {
  name: [{ required: true, message: '请输入集群名称', trigger: 'blur' }],
  kubeConfig: [
    {
      required: true,
      message: '请输入 KubeConfig',
      trigger: 'blur',
      validator: (rule: any, value: any, callback: any) => {
        // 新增模式必须填写，编辑模式可以留空
        if (!isEdit.value && authType.value === 'config' && !value) {
          callback(new Error('请输入 KubeConfig'))
        } else {
          callback()
        }
      }
    }
  ],
  apiEndpoint: [
    {
      required: true,
      message: '请输入 API Endpoint',
      trigger: 'blur',
      validator: (rule: any, value: any, callback: any) => {
        // 新增模式必须填写，编辑模式可以留空
        if (!isEdit.value && authType.value === 'token' && !value) {
          callback(new Error('请输入 API Endpoint'))
        } else {
          callback()
        }
      }
    }
  ],
  token: [
    {
      required: true,
      message: '请输入 Token',
      trigger: 'blur',
      validator: (rule: any, value: any, callback: any) => {
        // 新增模式必须填写，编辑模式可以留空
        if (!isEdit.value && authType.value === 'token' && !value) {
          callback(new Error('请输入 Token'))
        } else {
          callback()
        }
      }
    }
  ]
}

// 过滤后的集群列表
const filteredClusterList = computed(() => {
  let result = clusterList.value

  // 按关键词搜索（集群名称或别名）
  if (searchForm.keyword) {
    const keyword = searchForm.keyword.toLowerCase()
    result = result.filter(cluster =>
      cluster.name.toLowerCase().includes(keyword) ||
      cluster.alias.toLowerCase().includes(keyword)
    )
  }

  // 按状态筛选
  if (searchForm.status !== undefined) {
    result = result.filter(cluster => cluster.status === searchForm.status)
  }

  // 按版本筛选
  if (searchForm.version) {
    result = result.filter(cluster =>
      cluster.version.toLowerCase().includes(searchForm.version.toLowerCase())
    )
  }

  return result
})

// 加载集群列表
const loadClusters = async () => {
  loading.value = true
  try {
    const data = await getClusterList()
    clusterList.value = data || []
  } catch (error) {
    console.error(error)
    ElMessage.error('获取集群列表失败')
  } finally {
    loading.value = false
  }
}

// 搜索
const handleSearch = () => {
  // filteredClusterList 会自动更新
}

// 重置搜索
const handleReset = () => {
  searchForm.keyword = ''
  searchForm.status = undefined
  searchForm.version = ''
}

// 注册集群
const handleRegister = () => {
  isEdit.value = false
  kubeConfigEditable.value = true
  dialogVisible.value = true
}

// 查看集群详情
const handleViewDetail = (row: Cluster) => {
  router.push(`/kubernetes/clusters/${row.id}`)
}

// 编辑集群
const handleEdit = (row: Cluster) => {
  isEdit.value = true
  editClusterId.value = row.id
  kubeConfigEditable.value = true

  // 填充表单数据
  Object.assign(clusterForm, {
    name: row.name,
    alias: row.alias,
    apiEndpoint: row.apiEndpoint,
    kubeConfig: "", // 允许重新输入 KubeConfig
    token: "",
    provider: row.provider,
    region: row.region,
    description: row.description
  })

  dialogVisible.value = true
}

// 同步集群信息
const handleSync = async (row: Cluster) => {
  const loadingMsg = ElMessage.info({
    message: '正在同步集群信息...',
    duration: 0,
    type: 'info'
  })

  try {
    // 测试连接以更新版本和节点数
    await testClusterConnection(row.id)
    loadingMsg.close()

    // 重新加载列表
    await loadClusters()
    ElMessage.success('同步成功')
  } catch (error: any) {
    loadingMsg.close()
    ElMessage.error(error.response?.data?.message || '同步失败')
  }
}

// 认证方式切换
const handleAuthTypeChange = () => {
  formRef.value?.clearValidate()
  setTimeout(() => {
    formRef.value?.validate()
  }, 50)
}

// 更新行号
const updateLineCount = () => {
  const lines = clusterForm.kubeConfig.split('\n').length
  lineCount.value = lines || 1
}

// 更新 Token 行号
const updateTokenLineCount = () => {
  const lines = clusterForm.token.split('\n').length
  tokenLineCount.value = lines || 1
}

// 上传 KubeConfig 文件
const handleUploadKubeConfig = () => {
  fileInputRef.value?.click()
}

// 处理文件选择
const handleFileChange = (event: Event) => {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]

  if (!file) return

  const reader = new FileReader()
  reader.onload = (e) => {
    const content = e.target?.result as string
    clusterForm.kubeConfig = content
    updateLineCount()
    ElMessage.success('文件读取成功')
  }
  reader.onerror = () => {
    ElMessage.error('文件读取失败')
  }
  reader.readAsText(file)

  // 清空 input value，允许重复上传同一文件
  target.value = ''
}

// 提交表单
const handleSubmit = async () => {
  if (!formRef.value) return

  await formRef.value.validate(async (valid) => {
    if (valid) {
      submitLoading.value = true
      try {
        let kubeConfig = clusterForm.kubeConfig
        if (authType.value === 'token') {
          kubeConfig = buildKubeConfigFromToken(
            clusterForm.apiEndpoint,
            clusterForm.token
          )
        }

        if (isEdit.value && editClusterId.value) {
          // 编辑模式 - 可以更新名称、备注、服务商等信息
          // 如果需要更新 KubeConfig，在编辑模式下重新输入即可
          const updateData: any = {
            name: clusterForm.name,
            alias: clusterForm.alias,
            region: clusterForm.region,
            provider: clusterForm.provider,
            description: clusterForm.description
          }

          // 如果重新输入了 KubeConfig，则更新它
          if (clusterForm.kubeConfig && authType.value === 'config') {
            updateData.kubeConfig = clusterForm.kubeConfig
          } else if (clusterForm.token && authType.value === 'token') {
            updateData.kubeConfig = buildKubeConfigFromToken(
              clusterForm.apiEndpoint,
              clusterForm.token
            )
            updateData.apiEndpoint = clusterForm.apiEndpoint
          }

          await updateCluster(editClusterId.value, updateData)
          ElMessage.success('更新成功')
        } else {
          // 新增模式
          const requestData: any = {
            name: clusterForm.name,
            kubeConfig: kubeConfig
          }

          if (authType.value === 'token') {
            requestData.apiEndpoint = clusterForm.apiEndpoint
          }

          if (clusterForm.alias) requestData.alias = clusterForm.alias
          if (clusterForm.provider) requestData.provider = clusterForm.provider
          if (clusterForm.region) requestData.region = clusterForm.region
          if (clusterForm.description) requestData.description = clusterForm.description

          await createCluster(requestData)
          ElMessage.success('集群注册成功')
        }

        dialogVisible.value = false
        loadClusters()
      } catch (error: any) {
        ElMessage.error(error.response?.data?.message || '操作失败')
      } finally {
        submitLoading.value = false
      }
    }
  })
}

// 从 Token 构建 KubeConfig
const buildKubeConfigFromToken = (apiEndpoint: string, token: string) => {
  return `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ""
    server: ${apiEndpoint}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: default-user
  name: default-context
current-context: default-context
users:
- name: default-user
  user:
    token: ${token}
`
}

// 测试连接
const handleTestConnection = async (row: Cluster) => {
  const loadingMsg = ElMessage.info({
    message: '正在测试连接...',
    duration: 0,
    type: 'info'
  })

  try {
    const result = await testClusterConnection(row.id)
    loadingMsg.close()

    // 重新加载列表以更新节点数
    await loadClusters()

    ElMessage.success(`连接成功！版本: ${result.version}`)
  } catch (error: any) {
    loadingMsg.close()
    ElMessage.error(error.response?.data?.message || '连接失败')
  }
}

// 删除集群
const handleDelete = async (row: Cluster) => {
  try {
    await ElMessageBox.confirm('确定要删除该集群吗？此操作不可恢复！', '提示', {
      type: 'warning',
      confirmButtonText: '确定',
      cancelButtonText: '取消'
    })

    await deleteCluster(row.id)
    ElMessage.success('删除成功')
    loadClusters()
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error(error.response?.data?.message || '删除失败')
    }
  }
}

// 查看集群凭证
const handleViewConfig = async (row: Cluster) => {
  try {
    const cluster = await getClusterDetail(row.id)
    currentCluster.value = cluster

    // 获取解密后的 KubeConfig
    const config = await getClusterConfig(row.id)
    currentConfig.value = config

    configDialogVisible.value = true
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || '获取集群凭证失败')
  }
}

// 监听 config 内容变化，更新行号
watch(currentConfig, () => {
  const lines = currentConfig.value.split('\n').length
  configLineCount.value = lines || 1
})

// 复制配置
const handleCopyConfig = async () => {
  try {
    await navigator.clipboard.writeText(currentConfig.value)
    ElMessage.success('复制成功')
  } catch (error) {
    ElMessage.error('复制失败，请手动复制')
  }
}

// 下载配置
const handleDownloadConfig = () => {
  const blob = new Blob([currentConfig.value], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  const filename = `kubeconfig-${currentCluster.value?.name || 'cluster'}.conf`

  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)

  ElMessage.success('下载成功')
}

// 关闭对话框
const handleDialogClose = () => {
  formRef.value?.resetFields()
  Object.assign(clusterForm, {
    name: '',
    alias: '',
    apiEndpoint: '',
    kubeConfig: '',
    token: '',
    provider: 'native',
    region: '',
    description: ''
  })
  authType.value = 'config'
  isEdit.value = false
  editClusterId.value = undefined
  kubeConfigEditable.value = true
}

// 获取状态类型
const getStatusType = (status: number) => {
  const statusMap: Record<number, string> = {
    1: 'success',
    2: 'danger',
    3: 'info'
  }
  return statusMap[status] || 'info'
}

// 获取状态文本
const getStatusText = (status: number) => {
  const statusMap: Record<number, string> = {
    1: '正常',
    2: '连接失败',
    3: '不可用'
  }
  return statusMap[status] || '未知'
}

// 获取服务商文本
const getProviderText = (provider: string) => {
  const providerMap: Record<string, string> = {
    native: '自建集群',
    aliyun: '阿里云 ACK',
    tencent: '腾讯云 TKE',
    aws: 'AWS EKS'
  }
  return providerMap[provider] || provider || '未配置'
}

onMounted(() => {
  loadClusters()
})
</script>

<style scoped>
.clusters-container {
  padding: 20px;
  background-color: #fff;
  min-height: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid #e6e6e6;
}

.page-title {
  margin: 0;
  font-size: 18px;
  font-weight: 500;
  color: #303133;
}

.search-bar {
  margin-bottom: 20px;
  padding: 12px 16px;
  background-color: #f5f7fa;
  border-radius: 4px;
  display: flex;
  align-items: center;
}

.search-bar :deep(.el-form-item) {
  margin-bottom: 0;
}

.black-button {
  background-color: #000000 !important;
  color: #ffffff !important;
  border-color: #000000 !important;
}

.black-button:hover {
  background-color: #333333 !important;
  border-color: #333333 !important;
}

.form-section {
  margin-bottom: 24px;
  padding-bottom: 20px;
  border-bottom: 1px dashed #dcdfe6;
}

.form-section:last-of-type {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}

.section-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 16px;
  padding-left: 8px;
  border-left: 3px solid #000000;
}

.code-editor-wrapper {
  display: flex;
  width: 100%;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  overflow: hidden;
  background-color: #282c34;
}

.line-numbers {
  display: flex;
  flex-direction: column;
  padding: 12px 8px;
  background-color: #21252b;
  border-right: 1px solid #3e4451;
  user-select: none;
  min-width: 40px;
  text-align: right;
}

.line-number {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 13px;
  line-height: 1.6;
  color: #5c6370;
  min-height: 20.8px;
}

.code-textarea {
  flex: 1;
  min-height: 200px;
  padding: 12px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 13px;
  line-height: 1.6;
  color: #abb2bf;
  background-color: #282c34;
  border: none;
  outline: none;
  resize: vertical;
  font-feature-settings: "liga" 0;
}

.code-textarea::placeholder {
  color: #5c6370;
}

.code-textarea:focus {
  background-color: #282c34;
  color: #abb2bf;
}

.code-tip {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
  padding: 8px 12px;
  background-color: #f4f4f5;
  border-radius: 4px;
  font-size: 12px;
  color: #606266;
}

.code-tip .el-icon {
  color: #409eff;
  font-size: 14px;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

.cluster-dialog :deep(.el-dialog__body) {
  padding: 20px 24px;
}

.cluster-dialog :deep(.el-form-item) {
  margin-bottom: 18px;
}

.cluster-dialog :deep(.el-form-item__label) {
  font-weight: 500;
  color: #606266;
}

.cluster-dialog :deep(.el-radio-group) {
  display: flex;
  gap: 0;
}

.cluster-dialog :deep(.el-radio-button) {
  flex: 1;
}

.cluster-dialog :deep(.el-radio-button__inner) {
  width: 100%;
  border-radius: 0;
}

.cluster-dialog :deep(.el-radio-button:first-child .el-radio-button__inner) {
  border-radius: 4px 0 0 4px;
}

.cluster-dialog :deep(.el-radio-button:last-child .el-radio-button__inner) {
  border-radius: 0 4px 4px 0;
}

.cluster-name-link {
  color: #303133;
  transition: color 0.3s;
}

.cluster-name-link:hover {
  color: #409EFF;
}
</style>
