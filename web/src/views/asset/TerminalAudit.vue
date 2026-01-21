<template>
  <div class="terminal-audit-container">
    <div class="header">
      <h2>终端审计</h2>
      <p class="subtitle">查看和管理SSH终端会话录制</p>
    </div>

    <!-- 搜索和操作栏 -->
    <div class="search-bar">
      <el-input
        v-model="searchKeyword"
        placeholder="搜索主机名、IP或用户名"
        style="width: 300px"
        clearable
        @clear="loadSessions"
        @keyup.enter="loadSessions"
      >
        <template #prefix>
          <el-icon><Search /></el-icon>
        </template>
      </el-input>
      <el-button type="primary" @click="loadSessions" style="margin-left: 10px">
        <el-icon><Search /></el-icon>
        搜索
      </el-button>
      <el-button @click="handleRefresh" :loading="loading">
        <el-icon><Refresh /></el-icon>
        刷新
      </el-button>
    </div>

    <!-- 终端会话列表 -->
    <el-table
      :data="sessions"
      v-loading="loading"
      style="width: 100%; margin-top: 20px"
      stripe
      border
    >
      <el-table-column prop="id" label="ID" width="80" align="center" />

      <el-table-column label="主机信息" min-width="200">
        <template #default="{ row }">
          <div class="host-info">
            <div class="host-name">
              <el-icon><Monitor /></el-icon>
              <span>{{ row.hostName }}</span>
            </div>
            <div class="host-ip">{{ row.hostIp }}</div>
          </div>
        </template>
      </el-table-column>

      <el-table-column prop="username" label="操作用户" width="120" align="center">
        <template #default="{ row }">
          <el-tag type="info">
            <el-icon><User /></el-icon>
            {{ row.username }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column prop="durationText" label="时长" width="100" align="center" />

      <el-table-column prop="fileSizeText" label="文件大小" width="110" align="center" />

      <el-table-column prop="statusText" label="状态" width="100" align="center">
        <template #default="{ row }">
          <el-tag :type="getStatusType(row.status)">{{ row.statusText }}</el-tag>
        </template>
      </el-table-column>

      <el-table-column prop="createdAtText" label="创建时间" width="180" align="center" />

      <el-table-column label="操作" width="180" align="center" fixed="right">
        <template #default="{ row }">
          <el-button
            type="primary"
            link
            size="small"
            @click="handlePlay(row)"
            :loading="playingSession === row.id"
          >
            <el-icon><VideoPlay /></el-icon>
            播放
          </el-button>
          <el-popconfirm
            title="确定删除此会话录制吗？"
            @confirm="handleDelete(row.id)"
            width="220"
          >
            <template #reference>
              <el-button
                type="danger"
                link
                size="small"
                :loading="deletingSession === row.id"
              >
                <el-icon><Delete /></el-icon>
                删除
              </el-button>
            </template>
          </el-popconfirm>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pagination-container">
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="total"
        layout="total, sizes, prev, pager, next, jumper"
        @size-change="handleSizeChange"
        @current-change="handlePageChange"
      />
    </div>

    <!-- 播放对话框 -->
    <el-dialog
      v-model="playerVisible"
      :title="`终端回放 - ${currentSession?.hostName}`"
      width="80%"
      top="5vh"
      @close="handlePlayerClose"
    >
      <AsciinemaPlayer
        v-if="recordingUrl && playerVisible"
        :src="recordingUrl"
        :autoplay="true"
      />
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Search,
  Refresh,
  Monitor,
  User,
  VideoPlay,
  Delete
} from '@element-plus/icons-vue'
import { getTerminalSessions, playTerminalSession, deleteTerminalSession } from '@/api/terminal'
import AsciinemaPlayer from '@/components/AsciinemaPlayer.vue'

interface TerminalSession {
  id: number
  hostId: number
  hostName: string
  hostIp: string
  userId: number
  username: string
  duration: number
  durationText: string
  fileSize: number
  fileSizeText: string
  status: string
  statusText: string
  createdAt: string
  createdAtText: string
}

const loading = ref(false)
const sessions = ref<TerminalSession[]>([])
const searchKeyword = ref('')
const page = ref(1)
const pageSize = ref(10)
const total = ref(0)

// 播放相关
const playerVisible = ref(false)
const recordingUrl = ref('')
const currentSession = ref<TerminalSession | null>(null)
const playingSession = ref(0)

// 删除相关
const deletingSession = ref(0)

// 加载会话列表
const loadSessions = async () => {
  loading.value = true
  try {
    const response = await getTerminalSessions({
      page: page.value,
      pageSize: pageSize.value,
      keyword: searchKeyword.value
    })
    sessions.value = response.list || []
    total.value = response.total || 0
  } catch (error: any) {
    ElMessage.error('加载会话列表失败: ' + (error.message || '未知错误'))
  } finally {
    loading.value = false
  }
}

// 播放会话
const handlePlay = async (session: TerminalSession) => {
  playingSession.value = session.id
  try {
    const response = await playTerminalSession(session.id)

    // 创建Blob URL
    const blob = new Blob([response], { type: 'application/json' })
    recordingUrl.value = URL.createObjectURL(blob)
    currentSession.value = session
    playerVisible.value = true
  } catch (error: any) {
    ElMessage.error('加载录制文件失败: ' + (error.message || '未知错误'))
  } finally {
    playingSession.value = 0
  }
}

// 删除会话
const handleDelete = async (id: number) => {
  deletingSession.value = id
  try {
    await deleteTerminalSession(id)
    ElMessage.success('删除成功')
    loadSessions()
  } catch (error: any) {
    ElMessage.error('删除失败: ' + (error.message || '未知错误'))
  } finally {
    deletingSession.value = 0
  }
}

// 刷新
const handleRefresh = () => {
  searchKeyword.value = ''
  page.value = 1
  loadSessions()
}

// 分页变化
const handleSizeChange = () => {
  page.value = 1
  loadSessions()
}

const handlePageChange = () => {
  loadSessions()
}

// 关闭播放器
const handlePlayerClose = () => {
  if (recordingUrl.value) {
    URL.revokeObjectURL(recordingUrl.value)
    recordingUrl.value = ''
  }
  currentSession.value = null
}

// 获取状态类型
const getStatusType = (status: string): 'success' | 'info' | 'warning' | 'danger' => {
  const typeMap: Record<string, 'success' | 'info' | 'warning' | 'danger'> = {
    completed: 'success',
    recording: 'warning',
    failed: 'danger'
  }
  return typeMap[status] || 'info'
}

onMounted(() => {
  loadSessions()
})
</script>

<style scoped lang="scss">
.terminal-audit-container {
  padding: 20px;
  background: #fff;
  border-radius: 8px;
  min-height: calc(100vh - 100px);

  .header {
    margin-bottom: 20px;

    h2 {
      margin: 0;
      font-size: 24px;
      color: #303133;
    }

    .subtitle {
      margin: 8px 0 0 0;
      font-size: 14px;
      color: #909399;
    }
  }

  .search-bar {
    display: flex;
    align-items: center;
    margin-bottom: 20px;
  }

  .host-info {
    .host-name {
      display: flex;
      align-items: center;
      gap: 6px;
      font-weight: 500;
      color: #303133;
      margin-bottom: 4px;

      .el-icon {
        color: #409eff;
      }
    }

    .host-ip {
      font-size: 12px;
      color: #909399;
      font-family: 'Consolas', 'Monaco', monospace;
    }
  }

  .pagination-container {
    margin-top: 20px;
    display: flex;
    justify-content: flex-end;
  }

  :deep(.el-dialog__body) {
    padding: 20px;
    background: #000;
  }
}
</style>
