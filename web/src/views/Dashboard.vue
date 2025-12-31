<template>
  <div class="dashboard">
    <!-- 顶部统计卡片 -->
    <el-row :gutter="20" class="stats-row">
      <el-col :span="6" v-for="(stat, index) in topStats" :key="index">
        <el-card class="stat-card" shadow="hover">
          <div class="stat-content">
            <div class="stat-icon" :style="{ backgroundColor: stat.color }">
              <el-icon :size="32" :color="'#fff'">
                <component :is="stat.icon" />
              </el-icon>
            </div>
            <div class="stat-info">
              <div class="stat-value">{{ stat.value }}</div>
              <div class="stat-label">{{ stat.label }}</div>
              <div class="stat-trend" :class="stat.trendClass">
                <el-icon><ArrowUp v-if="stat.trend === 'up'" /><ArrowDown v-else /></el-icon>
                {{ stat.trendValue }}
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 资产详情 & 服务详情 -->
    <el-row :gutter="20" class="detail-row">
      <el-col :span="12">
        <el-card class="detail-card" shadow="hover">
          <template #header>
            <div class="card-header">
              <span class="card-title">资产详情</span>
              <el-button type="primary" link size="small">查看全部</el-button>
            </div>
          </template>
          <el-table :data="assets" style="width: 100%" size="small">
            <el-table-column prop="name" label="资产名称" min-width="150" />
            <el-table-column prop="type" label="类型" min-width="100">
              <template #default="{ row }">
                <el-tag :type="getTypeColor(row.type)" size="small">{{ row.type }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="ip" label="IP地址" min-width="140" />
            <el-table-column prop="status" label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="row.status === '正常' ? 'success' : 'danger'" size="small">
                  {{ row.status }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="cpu" label="CPU" min-width="80" />
            <el-table-column prop="memory" label="内存" min-width="80" />
          </el-table>
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card class="detail-card" shadow="hover">
          <template #header>
            <div class="card-header">
              <span class="card-title">服务详情</span>
              <el-button type="primary" link size="small">查看全部</el-button>
            </div>
          </template>
          <el-table :data="services" style="width: 100%" size="small">
            <el-table-column prop="name" label="服务名称" min-width="150" />
            <el-table-column prop="port" label="端口" min-width="80" />
            <el-table-column prop="status" label="状态" width="80">
              <template #default="{ row }">
                <el-tag :type="getStatusType(row.status)" size="small">
                  {{ row.status }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="instances" label="实例数" min-width="80" />
            <el-table-column prop="uptime" label="运行时间" min-width="150" />
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <!-- 发布详情 & 监控告警 -->
    <el-row :gutter="20" class="detail-row">
      <el-col :span="12">
        <el-card class="detail-card" shadow="hover">
          <template #header>
            <div class="card-header">
              <span class="card-title">发布详情</span>
              <el-button type="primary" link size="small">查看全部</el-button>
            </div>
          </template>
          <el-timeline>
            <el-timeline-item
              v-for="(deploy, index) in deployments"
              :key="index"
              :timestamp="deploy.time"
              :type="deploy.type"
              placement="top"
            >
              <div class="deploy-item">
                <div class="deploy-header">
                  <span class="deploy-name">{{ deploy.name }}</span>
                  <el-tag :type="getDeployStatusType(deploy.status)" size="small">
                    {{ deploy.status }}
                  </el-tag>
                </div>
                <div class="deploy-info">
                  <span>版本：{{ deploy.version }}</span>
                  <span>环境：{{ deploy.env }}</span>
                </div>
                <div class="deploy-user">操作人：{{ deploy.user }}</div>
              </div>
            </el-timeline-item>
          </el-timeline>
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card class="detail-card alarm-card" shadow="hover">
          <template #header>
            <div class="card-header">
              <span class="card-title">监控告警</span>
              <el-button type="primary" link size="small">查看全部</el-button>
            </div>
          </template>
          <div class="alarm-list">
            <div
              v-for="(alarm, index) in alarms"
              :key="index"
              class="alarm-item"
              :class="'alarm-' + alarm.level"
            >
              <div class="alarm-header">
                <el-icon class="alarm-icon">
                  <Warning v-if="alarm.level === 'high'" />
                  <WarningFilled v-else-if="alarm.level === 'medium'" />
                  <InfoFilled v-else />
                </el-icon>
                <span class="alarm-title">{{ alarm.title }}</span>
                <el-tag :type="getAlarmTagType(alarm.level)" size="small">
                  {{ getAlarmLevelText(alarm.level) }}
                </el-tag>
              </div>
              <div class="alarm-content">{{ alarm.content }}</div>
              <div class="alarm-footer">
                <span class="alarm-time">{{ alarm.time }}</span>
                <span class="alarm-source">来源：{{ alarm.source }}</span>
              </div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import {
  OfficeBuilding,
  Connection,
  Monitor,
  Warning,
  ArrowUp,
  ArrowDown,
  WarningFilled,
  InfoFilled,
  Platform
} from '@element-plus/icons-vue'

// 顶部统计数据
const topStats = ref([
  {
    label: '资产总数',
    value: '156',
    icon: OfficeBuilding,
    color: '#409EFF',
    trend: 'up',
    trendValue: '12',
    trendClass: 'trend-up'
  },
  {
    label: '运行服务',
    value: '42',
    icon: Platform,
    color: '#67C23A',
    trend: 'up',
    trendValue: '5',
    trendClass: 'trend-up'
  },
  {
    label: '今日发布',
    value: '8',
    icon: Monitor,
    color: '#E6A23C',
    trend: 'down',
    trendValue: '3',
    trendClass: 'trend-down'
  },
  {
    label: '活跃告警',
    value: '3',
    icon: Warning,
    color: '#F56C6C',
    trend: 'down',
    trendValue: '15%',
    trendClass: 'trend-up'
  }
])

// 资产详情
const assets = ref([
  { name: 'web-server-01', type: '服务器', ip: '192.168.1.10', status: '正常', cpu: '45%', memory: '62%' },
  { name: 'web-server-02', type: '服务器', ip: '192.168.1.11', status: '正常', cpu: '38%', memory: '55%' },
  { name: 'db-master', type: '数据库', ip: '192.168.1.20', status: '正常', cpu: '52%', memory: '78%' },
  { name: 'db-slave-01', type: '数据库', ip: '192.168.1.21', status: '正常', cpu: '35%', memory: '65%' },
  { name: 'redis-cluster', type: '缓存', ip: '192.168.1.30', status: '异常', cpu: '89%', memory: '92%' },
  { name: 'nginx-lb', type: '负载均衡', ip: '192.168.1.5', status: '正常', cpu: '22%', memory: '38%' }
])

// 服务详情
const services = ref([
  { name: 'opshub-api', port: 9876, status: '运行中', instances: 3, uptime: '15天3小时' },
  { name: 'opshub-web', port: 5173, status: '运行中', instances: 2, uptime: '15天3小时' },
  { name: 'mysql-master', port: 3306, status: '运行中', instances: 1, uptime: '30天12小时' },
  { name: 'redis-cache', port: 6379, status: '运行中', instances: 1, uptime: '25天8小时' },
  { name: 'nginx-proxy', port: 80, status: '运行中', instances: 2, uptime: '45天6小时' },
  { name: 'prometheus', port: 9090, status: '已停止', instances: 0, uptime: '-' }
])

// 发布详情
const deployments = ref([
  {
    name: 'opshub-api',
    version: 'v1.2.3',
    env: '生产环境',
    status: '成功',
    user: '张三',
    time: '2025-12-30 12:30:00',
    type: 'success'
  },
  {
    name: 'opshub-web',
    version: 'v1.2.3',
    env: '生产环境',
    status: '成功',
    user: '李四',
    time: '2025-12-30 11:45:00',
    type: 'success'
  },
  {
    name: 'opshub-api',
    version: 'v1.2.2',
    env: '测试环境',
    status: '成功',
    user: '王五',
    time: '2025-12-30 10:20:00',
    type: 'success'
  },
  {
    name: 'payment-service',
    version: 'v2.1.0',
    env: '预发布环境',
    status: '进行中',
    user: '赵六',
    time: '2025-12-30 09:15:00',
    type: 'primary'
  },
  {
    name: 'user-service',
    version: 'v1.0.5',
    env: '生产环境',
    status: '失败',
    user: '张三',
    time: '2025-12-30 08:30:00',
    type: 'danger'
  }
])

// 监控告警
const alarms = ref([
  {
    title: 'CPU使用率过高',
    content: 'redis-cluster 服务器 CPU 使用率超过 85%',
    level: 'high',
    source: 'Prometheus',
    time: '2025-12-30 12:28:00'
  },
  {
    title: '磁盘空间不足',
    content: 'web-server-01 磁盘使用率达到 88%，建议及时清理',
    level: 'medium',
    source: 'Zabbix',
    time: '2025-12-30 11:50:00'
  },
  {
    title: '服务响应缓慢',
    content: 'opshub-api 接口平均响应时间超过 2s',
    level: 'medium',
    source: 'Grafana',
    time: '2025-12-30 10:35:00'
  },
  {
    title: '内存使用率告警',
    content: 'db-master 内存使用率达到 78%',
    level: 'low',
    source: 'Prometheus',
    time: '2025-12-30 09:20:00'
  },
  {
    title: '网络连接数异常',
    content: 'nginx-proxy 当前连接数超过阈值',
    level: 'low',
    source: 'Zabbix',
    time: '2025-12-30 08:45:00'
  }
])

// 辅助函数
const getTypeColor = (type: string) => {
  const colorMap: Record<string, string> = {
    '服务器': 'primary',
    '数据库': 'success',
    '缓存': 'warning',
    '负载均衡': 'info'
  }
  return colorMap[type] || ''
}

const getStatusType = (status: string) => {
  const statusMap: Record<string, string> = {
    '运行中': 'success',
    '已停止': 'danger',
    '异常': 'warning'
  }
  return statusMap[status] || 'info'
}

const getDeployStatusType = (status: string) => {
  const statusMap: Record<string, string> = {
    '成功': 'success',
    '进行中': 'primary',
    '失败': 'danger',
    '待发布': 'info'
  }
  return statusMap[status] || 'info'
}

const getAlarmTagType = (level: string) => {
  const levelMap: Record<string, string> = {
    'high': 'danger',
    'medium': 'warning',
    'low': 'info'
  }
  return levelMap[level] || 'info'
}

const getAlarmLevelText = (level: string) => {
  const textMap: Record<string, string> = {
    'high': '严重',
    'medium': '警告',
    'low': '提示'
  }
  return textMap[level] || level
}
</script>

<style scoped>
.dashboard {
  padding: 0;
  background-color: transparent;
}

.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  border-radius: 8px;
  overflow: hidden;
}

.stat-card :deep(.el-card__body) {
  padding: 20px;
}

.stat-content {
  display: flex;
  align-items: center;
}

.stat-icon {
  width: 64px;
  height: 64px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-right: 16px;
}

.stat-info {
  flex: 1;
}

.stat-value {
  font-size: 28px;
  font-weight: bold;
  color: #303133;
  line-height: 1;
  margin-bottom: 8px;
}

.stat-label {
  font-size: 14px;
  color: #909399;
  margin-bottom: 8px;
}

.stat-trend {
  font-size: 13px;
  display: flex;
  align-items: center;
  gap: 4px;
}

.trend-up {
  color: #67C23A;
}

.trend-down {
  color: #F56C6C;
}

.detail-row {
  margin-bottom: 20px;
}

.detail-card {
  border-radius: 8px;
  height: 100%;
}

.detail-card :deep(.el-card__header) {
  padding: 15px 20px;
  border-bottom: 1px solid #ebeef5;
}

.detail-card :deep(.el-card__body) {
  padding: 20px;
  max-height: 480px;
  overflow-y: auto;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-title {
  font-size: 16px;
  font-weight: 500;
  color: #303133;
}

/* 部署详情样式 */
:deep(.el-timeline) {
  padding-left: 10px;
}

:deep(.el-timeline-item__timestamp) {
  color: #909399;
  font-size: 13px;
}

:deep(.el-timeline-item__wrapper) {
  padding-left: 28px;
}

.deploy-item {
  margin-bottom: 10px;
}

.deploy-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}

.deploy-name {
  font-weight: 500;
  color: #303133;
  font-size: 14px;
}

.deploy-info {
  font-size: 13px;
  color: #606266;
  margin-bottom: 4px;
}

.deploy-info span {
  margin-right: 15px;
}

.deploy-user {
  font-size: 12px;
  color: #909399;
}

/* 告警样式 */
.alarm-card :deep(.el-card__body) {
  padding: 15px 20px;
}

.alarm-list {
  max-height: 420px;
  overflow-y: auto;
}

.alarm-item {
  padding: 12px;
  margin-bottom: 12px;
  border-radius: 6px;
  border-left: 3px solid;
  background-color: #f5f7fa;
  transition: all 0.3s;
}

.alarm-item:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.alarm-item:last-child {
  margin-bottom: 0;
}

.alarm-high {
  border-left-color: #F56C6C;
  background-color: #fef0f0;
}

.alarm-medium {
  border-left-color: #E6A23C;
  background-color: #fdf6ec;
}

.alarm-low {
  border-left-color: #409EFF;
  background-color: #ecf5ff;
}

.alarm-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.alarm-icon {
  font-size: 18px;
}

.alarm-high .alarm-icon {
  color: #F56C6C;
}

.alarm-medium .alarm-icon {
  color: #E6A23C;
}

.alarm-low .alarm-icon {
  color: #409EFF;
}

.alarm-title {
  flex: 1;
  font-weight: 500;
  color: #303133;
  font-size: 14px;
}

.alarm-content {
  font-size: 13px;
  color: #606266;
  line-height: 1.6;
  margin-bottom: 8px;
  padding-left: 26px;
}

.alarm-footer {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  color: #909399;
  padding-left: 26px;
}

/* 表格样式优化 */
:deep(.el-table) {
  font-size: 13px;
}

:deep(.el-table th) {
  background-color: #fafafa;
}

/* 滚动条美化 */
.detail-card :deep(.el-card__body),
.alarm-list {
  scrollbar-width: thin;
  scrollbar-color: #dcdfe6 transparent;
}

.detail-card :deep(.el-card__body)::-webkit-scrollbar,
.alarm-list::-webkit-scrollbar {
  width: 6px;
}

.detail-card :deep(.el-card__body)::-webkit-scrollbar-thumb,
.alarm-list::-webkit-scrollbar-thumb {
  background-color: #dcdfe6;
  border-radius: 3px;
}

.detail-card :deep(.el-card__body)::-webkit-scrollbar-thumb:hover,
.alarm-list::-webkit-scrollbar-thumb:hover {
  background-color: #c0c4cc;
}

/* 响应式设计 */
@media (max-width: 1200px) {
  .stat-value {
    font-size: 24px;
  }

  .stat-icon {
    width: 56px;
    height: 56px;
  }
}
</style>
