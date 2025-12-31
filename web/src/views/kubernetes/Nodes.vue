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

    <!-- 节点列表 -->
    <el-table :data="nodeList" border stripe v-loading="loading" style="width: 100%">
      <el-table-column prop="name" label="名称" min-width="200" />
      <el-table-column label="状态" width="120">
        <template #default="{ row }">
          <el-tag :type="row.status === 'Ready' ? 'success' : 'danger'">
            {{ row.status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="roles" label="角色" width="120" />
      <el-table-column prop="internalIP" label="IP地址" width="150" />
      <el-table-column prop="version" label="版本" width="100" />
      <el-table-column prop="osImage" label="操作系统" min-width="200" />
      <el-table-column prop="containerRuntime" label="容器运行时" width="150" />
      <el-table-column prop="age" label="年龄" width="100" />
      <el-table-column label="操作" width="100" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="handleViewDetails(row)">详情</el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getClusterList, type Cluster, getNodes, type NodeInfo } from '@/api/kubernetes'

const loading = ref(false)
const clusterList = ref<Cluster[]>([])
const selectedClusterId = ref<number>()
const nodeList = ref<NodeInfo[]>([])

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
    nodeList.value = data || []
  } catch (error) {
    console.error(error)
    ElMessage.error('获取节点列表失败')
  } finally {
    loading.value = false
  }
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
</style>
