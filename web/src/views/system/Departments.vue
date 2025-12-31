<template>
  <div class="departments-container">
    <!-- 页面标题和操作按钮 -->
    <div class="page-header">
      <h2 class="page-title">部门管理</h2>
      <el-button class="black-button" @click="handleAdd">新增部门</el-button>
    </div>

    <el-table
      :data="deptList"
      border
      stripe
      v-loading="loading"
      row-key="id"
      :tree-props="{ children: 'children', hasChildren: 'hasChildren' }"
      style="width: 100%"
    >
      <el-table-column prop="name" label="部门名称" min-width="200" />
      <el-table-column prop="code" label="部门编码" min-width="150" />
      <el-table-column label="状态" width="80">
        <template #default="{ row }">
          <el-tag :type="row.status === 1 ? 'success' : 'danger'">
            {{ row.status === 1 ? '启用' : '禁用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="sort" label="排序" width="80" />
      <el-table-column label="操作" width="200" fixed="right">
        <template #default="{ row }">
          <el-button class="black-button" size="small" @click="handleEdit(row)">编辑</el-button>
          <el-button type="danger" size="small" @click="handleDelete(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 新增/编辑对话框 -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="600px">
      <el-form :model="deptForm" :rules="rules" ref="formRef" label-width="100px">
        <el-form-item label="部门名称" prop="name">
          <el-input v-model="deptForm.name" />
        </el-form-item>
        <el-form-item label="部门编码" prop="code">
          <el-input v-model="deptForm.code" />
        </el-form-item>
        <el-form-item label="上级部门" prop="parentId">
          <el-cascader
            v-model="deptForm.parentId"
            :options="deptTreeOptions"
            :props="{ checkStrictly: true, value: 'id', label: 'name' }"
            clearable
            placeholder="请选择上级部门"
          />
        </el-form-item>
        <el-form-item label="排序" prop="sort">
          <el-input-number v-model="deptForm.sort" :min="0" />
        </el-form-item>
        <el-form-item label="状态" prop="status">
          <el-radio-group v-model="deptForm.status">
            <el-radio :label="1">启用</el-radio>
            <el-radio :label="0">禁用</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" @click="handleSubmit">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox, FormInstance } from 'element-plus'
import { getDepartmentTree, createDepartment, updateDepartment, deleteDepartment } from '@/api/department'

const loading = ref(false)
const dialogVisible = ref(false)
const dialogTitle = ref('')
const isEdit = ref(false)
const formRef = ref<FormInstance>()

const deptList = ref([])
const deptTreeOptions = ref([])

const deptForm = reactive({
  id: 0,
  name: '',
  code: '',
  parentId: 0,
  sort: 0,
  status: 1
})

const rules = {
  name: [{ required: true, message: '请输入部门名称', trigger: 'blur' }],
  code: [{ required: true, message: '请输入部门编码', trigger: 'blur' }]
}

const loadDepartments = async () => {
  loading.value = true
  try {
    const res = await getDepartmentTree()
    deptList.value = res || []
    deptTreeOptions.value = JSON.parse(JSON.stringify(res || []))
    // 添加根节点选项
    deptTreeOptions.value.unshift({ id: 0, name: '顶级部门' })
  } finally {
    loading.value = false
  }
}

const handleAdd = () => {
  isEdit.value = false
  dialogTitle.value = '新增部门'
  dialogVisible.value = true
}

const handleEdit = (row: any) => {
  isEdit.value = true
  dialogTitle.value = '编辑部门'
  Object.assign(deptForm, row)
  dialogVisible.value = true
}

const handleDelete = async (row: any) => {
  try {
    await ElMessageBox.confirm('确定要删除该部门吗？', '提示', { type: 'warning' })
    await deleteDepartment(row.id)
    ElMessage.success('删除成功')
    loadDepartments()
  } catch (error) {
    if (error !== 'cancel') console.error(error)
  }
}

const handleSubmit = async () => {
  if (!formRef.value) return
  await formRef.value.validate(async (valid) => {
    if (valid) {
      try {
        const data = { ...deptForm }
        // 处理 parentId，如果是数组取最后一个值
        if (Array.isArray(data.parentId)) {
          data.parentId = data.parentId[data.parentId.length - 1] || 0
        }

        if (isEdit.value) {
          await updateDepartment(deptForm.id, data)
        } else {
          await createDepartment(data)
        }
        ElMessage.success('操作成功')
        dialogVisible.value = false
        loadDepartments()
      } catch (error) {
        console.error(error)
      }
    }
  })
}

onMounted(() => {
  loadDepartments()
})
</script>

<style scoped>
.departments-container {
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

/* 黑色按钮样式 */
.black-button {
  background-color: #000000 !important;
  color: #ffffff !important;
  border-color: #000000 !important;
}

.black-button:hover {
  background-color: #333333 !important;
  border-color: #333333 !important;
}

.black-button:focus {
  background-color: #000000 !important;
  border-color: #000000 !important;
}
</style>
