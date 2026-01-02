<template>
  <div class="nodes-container">
    <!-- 页面标题和操作 -->
    <div class="page-header">
      <h2 class="page-title">节点管理</h2>
      <el-select
        v-model="selectedClusterId"
        placeholder="选择集群"
        style="width: 300px"
        @change="handleClusterChange"
      >
        <el-option
          v-for="cluster in clusterList"
          :key="cluster.id"
          :label="cluster.alias || cluster.name"
          :value="cluster.id"
        />
      </el-select>
    </div>

    <!-- 搜索区域 -->
    <div class="search-section">
      <el-input
        v-model="searchName"
        placeholder="根据名称搜索"
        clearable
        style="width: 200px"
        @input="handleSearch"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
      <el-select
        v-model="searchStatus"
        placeholder="节点状态"
        clearable
        style="width: 150px"
        @change="handleSearch"
      >
        <el-option label="Ready" value="Ready" />
        <el-option label="NotReady" value="NotReady" />
      </el-select>
      <el-select
        v-model="searchRole"
        placeholder="节点角色"
        clearable
        style="width: 150px"
        @change="handleSearch"
      >
        <el-option label="master" value="master" />
        <el-option label="control-plane" value="control-plane" />
        <el-option label="worker" value="worker" />
      </el-select>
    </div>

    <!-- 节点列表 -->
    <el-table :data="filteredNodeList" border stripe v-loading="loading" style="width: 100%">
      <el-table-column label="节点名称" min-width="200" fixed="left">
        <template #default="{ row }">
          <div class="node-name-cell">
            <svg class="k8s-icon" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/>
              <path d="M12 4L8.5 7.5l1.41 1.41L12 6.83l2.09 2.08 1.41-1.41L12 4zm0 16l3.5-3.5-1.41-1.41L12 17.17l-2.09-2.08-1.41 1.41L12 20zM4 12l3.5-3.5-1.41-1.41L6.83 9 4 12l3.5 3.5 1.41-1.41L6.83 14.17 4 12zm16 0l-3.5 3.5 1.41 1.41L17.17 15 20 12l-3.5-3.5-1.41 1.41L17.17 9 20 12z"/>
            </svg>
            <span>{{ row.name }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag :type="row.status === 'Ready' ? 'success' : 'danger'">
            {{ row.status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="角色" width="150">
        <template #default="{ row }">
          <span :class="['role-badge', 'role-' + row.roles]">{{ row.roles }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="version" label="kubelet版本" width="150" />
      <el-table-column label="标签" width="100" align="center">
        <template #default="{ row }">
          <el-badge :value="Object.keys(row.labels || {}).length" class="label-badge">
            <el-icon class="label-icon" @click="showLabels(row)" size="20">
              <PriceTag />
            </el-icon>
          </el-badge>
        </template>
      </el-table-column>
      <el-table-column prop="age" label="运行时间" width="120" />
      <el-table-column label="CPU/内存" width="180">
        <template #default="{ row }">
          <div class="resource-cell">
            <div class="resource-item">
              <span class="resource-label">CPU:</span>
              <span class="resource-value">{{ row.cpuCapacity || '-' }}</span>
            </div>
            <div class="resource-item">
              <span class="resource-label">内存:</span>
              <span class="resource-value">{{ formatMemory(row.memoryCapacity) }}</span>
            </div>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="podCount" label="Pod数量" width="100" align="center">
        <template #default="{ row }">
          {{ row.podCount ?? 0 }}
        </template>
      </el-table-column>
      <el-table-column label="调度状态" width="120" align="center">
        <template #default="{ row }">
          <el-tag :type="row.schedulable ? 'success' : 'warning'">
            {{ row.schedulable ? '可调度' : '不可调度' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="taintCount" label="污点数量" width="100" align="center">
        <template #default="{ row }">
          {{ row.taintCount ?? 0 }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="100" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="handleViewDetails(row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 标签弹窗 -->
    <el-dialog
      v-model="labelDialogVisible"
      title="节点标签"
      width="600px"
    >
      <el-table :data="labelList" border>
        <el-table-column prop="key" label="Key" min-width="200" />
        <el-table-column prop="value" label="Value" min-width="300" />
      </el-table>
      <template #footer>
        <el-button @click="labelDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Search, PriceTag } from '@element-plus/icons-vue'
import { getClusterList, type Cluster, getNodes, type NodeInfo } from '@/api/kubernetes'

const loading = ref(false)
const clusterList = ref<Cluster[]>([])
const selectedClusterId = ref<number>()
const nodeList = ref<NodeInfo[]>([])

// 搜索条件
const searchName = ref('')
const searchStatus = ref('')
const searchRole = ref('')

// 标签弹窗
const labelDialogVisible = ref(false)
const labelList = ref<{ key: string; value: string }[]>([])

// 过滤后的节点列表
const filteredNodeList = computed(() => {
  let result = nodeList.value

  if (searchName.value) {
    result = result.filter(node =>
      node.name.toLowerCase().includes(searchName.value.toLowerCase())
    )
  }

  if (searchStatus.value) {
    result = result.filter(node => node.status === searchStatus.value)
  }

  if (searchRole.value) {
    result = result.filter(node => node.roles === searchRole.value)
  }

  return result
})

// 格式化内存显示
const formatMemory = (memory: string) => {
  if (!memory) return '-'
  // 内存格式如 "17179869184" (字节)
  const bytes = parseInt(memory)
  if (isNaN(bytes)) return memory

  const gb = bytes / (1024 * 1024 * 1024)
  if (gb >= 1) {
    return gb.toFixed(1) + 'Gi'
  }
  const mb = bytes / (1024 * 1024)
  return mb.toFixed(0) + 'Mi'
}

// 显示标签弹窗
const showLabels = (row: NodeInfo) => {
  const labels = row.labels || {}
  labelList.value = Object.keys(labels).map(key => ({
    key,
    value: labels[key]
  }))
  labelDialogVisible.value = true
}

// 加载集群列表
const loadClusters = async () => {
  try {
    const data = await getClusterList()
    clusterList.value = data || []
    if (clusterList.value.length > 0) {
      selectedClusterId.value = clusterList.value[0].id
      await loadNodes()
    }
  } catch (error) {
    console.error(error)
    ElMessage.error('获取集群列表失败')
  }
}

// 切换集群
const handleClusterChange = async () => {
  await loadNodes()
}

// 加载节点列表
const loadNodes = async () => {
  if (!selectedClusterId.value) return

  loading.value = true
  try {
    const data = await getNodes(selectedClusterId.value)
    console.log('节点数据:', data)
    nodeList.value = data || []
  } catch (error) {
    console.error(error)
    nodeList.value = []
    ElMessage.error('获取节点列表失败')
  } finally {
    loading.value = false
  }
}

// 处理搜索
const handleSearch = () => {
  // 搜索逻辑由 computed 自动处理
}

// 查看详情
const handleViewDetails = (row: NodeInfo) => {
  console.log('查看节点详情:', row)
  ElMessage.info('详情功能开发中...')
}

onMounted(() => {
  loadClusters()
})
</script>

<style scoped>
.nodes-container {
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

.search-section {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}

/* K8s 图标 */
.node-name-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.k8s-icon {
  width: 18px;
  height: 18px;
  color: #326ce5;
}

/* 角色标签样式 */
.role-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
}

.role-master {
  background-color: #e6f7ff;
  color: #1890ff;
  border: 1px solid #91d5ff;
}

.role-control-plane {
  background-color: #f6ffed;
  color: #52c41a;
  border: 1px solid #b7eb8f;
}

.role-worker {
  background-color: #f5f5f5;
  color: #595959;
  border: 1px solid #d9d9d9;
}

/* 标签图标 */
.label-badge {
  cursor: pointer;
}

.label-icon {
  color: #409eff;
  cursor: pointer;
  transition: color 0.3s;
}

.label-icon:hover {
  color: #66b1ff;
}

/* 资源显示 */
.resource-cell {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.resource-item {
  display: flex;
  align-items: center;
}

.resource-label {
  color: #909399;
  margin-right: 8px;
  font-size: 12px;
}

.resource-value {
  color: #303133;
  font-size: 13px;
}
</style>
