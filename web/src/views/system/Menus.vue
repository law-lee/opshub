<template>
  <div class="menus-container">
    <!-- 页面标题和操作按钮 -->
    <div class="page-header">
      <div>
        <h2 class="page-title">菜单管理</h2>
        <el-text type="info" size="small" style="margin-left: 10px;">
          （系统菜单 + 插件菜单）
        </el-text>
      </div>
      <el-button class="black-button" @click="handleAdd">新增菜单</el-button>
    </div>

    <el-table
      :data="menuList"
      border
      stripe
      v-loading="loading"
      row-key="id"
      :tree-props="{ children: 'children', hasChildren: 'hasChildren' }"
      style="width: 100%"
    >
      <el-table-column prop="name" label="菜单名称" min-width="200" />
      <el-table-column prop="code" label="菜单编码" min-width="150" />
      <el-table-column label="类型" width="150">
        <template #default="{ row }">
          <div style="display: flex; gap: 5px; flex-wrap: wrap;">
            <el-tag v-if="row.type === 1" type="success">目录</el-tag>
            <el-tag v-else-if="row.type === 2" type="primary">菜单</el-tag>
            <el-tag v-else type="info">按钮</el-tag>
            <el-tag v-if="row.isPlugin" type="warning" effect="plain">插件</el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="path" label="路由路径" min-width="200" />
      <el-table-column prop="icon" label="图标" width="100" />
      <el-table-column prop="sort" label="排序" width="80" />
      <el-table-column label="操作" width="200" fixed="right">
        <template #default="{ row }">
          <template v-if="row.isPlugin">
            <el-button class="black-button" size="small" @click="handleEditPluginSort(row)">调整排序</el-button>
            <el-tag type="warning" size="small" effect="plain">插件</el-tag>
          </template>
          <template v-else>
            <el-button class="black-button" size="small" @click="handleEdit(row)">编辑</el-button>
            <el-button type="danger" size="small" @click="handleDelete(row)">删除</el-button>
          </template>
        </template>
      </el-table-column>
    </el-table>

    <!-- 新增/编辑对话框 -->
    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="600px">
      <el-alert
        v-if="editingPluginMenu"
        title="插件菜单编辑"
        type="info"
        :closable="false"
        style="margin-bottom: 15px;"
      >
        <template #default>
          <div>您正在编辑插件菜单，只能修改排序字段</div>
          <div style="font-size: 12px; color: #666; margin-top: 5px;">
            菜单名称: {{ menuForm.name }} | 路径: {{ menuForm.path }}
          </div>
        </template>
      </el-alert>

      <el-form :model="menuForm" :rules="rules" ref="formRef" label-width="100px">
        <el-form-item label="菜单名称" prop="name">
          <el-input v-model="menuForm.name" :disabled="editingPluginMenu" />
        </el-form-item>
        <el-form-item label="菜单编码" prop="code">
          <el-input v-model="menuForm.code" :disabled="editingPluginMenu" />
        </el-form-item>
        <el-form-item label="类型" prop="type">
          <el-radio-group v-model="menuForm.type" :disabled="editingPluginMenu">
            <el-radio :label="1">目录</el-radio>
            <el-radio :label="2">菜单</el-radio>
            <el-radio :label="3">按钮</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="上级菜单" prop="parentId" v-if="!editingPluginMenu">
          <el-cascader
            v-model="menuForm.parentId"
            :options="menuTreeOptions"
            :props="{ checkStrictly: true, value: 'ID', label: 'name' }"
            clearable
            placeholder="请选择上级菜单"
          />
        </el-form-item>
        <el-form-item label="路由路径" prop="path" v-if="menuForm.type !== 3">
          <el-input v-model="menuForm.path" :disabled="editingPluginMenu" />
        </el-form-item>
        <el-form-item label="组件路径" prop="component" v-if="menuForm.type === 2 && !editingPluginMenu">
          <el-input v-model="menuForm.component" />
        </el-form-item>
        <el-form-item label="图标" prop="icon">
          <el-input v-model="menuForm.icon" :disabled="editingPluginMenu" />
        </el-form-item>
        <el-form-item label="排序" prop="sort">
          <el-input-number v-model="menuForm.sort" :min="0" />
          <span style="margin-left: 10px; color: #909399; font-size: 12px;">
            数值越小越靠前
          </span>
        </el-form-item>
        <el-form-item label="显示状态" prop="visible" v-if="!editingPluginMenu">
          <el-radio-group v-model="menuForm.visible">
            <el-radio :label="1">显示</el-radio>
            <el-radio :label="0">隐藏</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="状态" prop="status" v-if="!editingPluginMenu">
          <el-radio-group v-model="menuForm.status">
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
import { getMenuTree, createMenu, updateMenu, deleteMenu } from '@/api/menu'
import { pluginManager } from '@/plugins/manager'

const loading = ref(false)
const dialogVisible = ref(false)
const dialogTitle = ref('')
const isEdit = ref(false)
const editingPluginMenu = ref(false) // 标记是否正在编辑插件菜单
const formRef = ref<FormInstance>()

// 插件菜单排序存储 key
const PLUGIN_MENU_SORT_KEY = 'opshub_plugin_menu_sort'

const menuList = ref([])
const menuTreeOptions = ref([])

const menuForm = reactive({
  id: 0,
  name: '',
  code: '',
  type: 2,
  parentId: 0,
  path: '',
  component: '',
  icon: '',
  sort: 0,
  visible: 1,
  status: 1
})

const rules = {
  name: [{ required: true, message: '请输入菜单名称', trigger: 'blur' }],
  code: [{ required: true, message: '请输入菜单编码', trigger: 'blur' }],
  type: [{ required: true, message: '请选择类型', trigger: 'change' }]
}

// 加载插件菜单的自定义排序
const loadPluginMenuSort = (): Map<string, number> => {
  try {
    const stored = localStorage.getItem(PLUGIN_MENU_SORT_KEY)
    if (stored) {
      const sortMap = JSON.parse(stored)
      return new Map(Object.entries(sortMap))
    }
  } catch (error) {
    console.error('[菜单管理] 加载插件菜单排序失败:', error)
  }
  return new Map()
}

// 保存插件菜单的自定义排序
const savePluginMenuSort = (menuPath: string, sort: number) => {
  try {
    const sortMap = loadPluginMenuSort()
    sortMap.set(menuPath, sort)
    const sortObj = Object.fromEntries(sortMap)
    localStorage.setItem(PLUGIN_MENU_SORT_KEY, JSON.stringify(sortObj))
    console.log(`[菜单管理] 保存插件菜单排序: ${menuPath} = ${sort}`)
  } catch (error) {
    console.error('[菜单管理] 保存插件菜单排序失败:', error)
  }
}

// 构建插件菜单列表
const buildPluginMenuList = () => {
  const pluginMenus: any[] = []
  const installedPlugins = pluginManager.getInstalled()

  // 加载自定义排序
  const customSort = loadPluginMenuSort()
  console.log('[菜单管理] 已加载的自定义排序:', Object.fromEntries(customSort))

  console.log('[菜单管理] 已安装的插件:', installedPlugins.map(p => p.name))

  installedPlugins.forEach(plugin => {
    if (plugin.getMenus) {
      const menus = plugin.getMenus()
      console.log(`[菜单管理] 插件 ${plugin.name} 的菜单:`, menus)

      menus.forEach(menu => {
        // 如果有 parentPath 且不为空，则使用 parentPath 作为 parentId
        // 否则为顶级菜单，parentId 为 null
        const parentId = (menu.parentPath && menu.parentPath !== '') ? menu.parentPath : null

        // 优先使用自定义排序，如果没有则使用默认排序
        const sort = customSort.get(menu.path) ?? menu.sort

        pluginMenus.push({
          ID: menu.path, // 使用 path 作为 ID
          id: menu.path,
          name: menu.name,
          code: menu.path.replace(/\//g, '_'), // 将路径转换为编码
          type: menu.parentPath && menu.parentPath !== '' ? 2 : 1, // 有父路径的是菜单，否则是目录
          parentId: parentId,
          path: menu.path,
          component: '',
          icon: menu.icon,
          sort: sort, // 使用自定义排序或默认排序
          visible: menu.hidden ? 0 : 1,
          status: 1,
          isPlugin: true, // 标记为插件菜单
          pluginName: plugin.name,
          children: []
        })

        console.log(`[菜单管理] 构建插件菜单: ${menu.name}`, {
          ID: menu.path,
          parentId: parentId,
          type: menu.parentPath && menu.parentPath !== '' ? 2 : 1,
          sort: sort,
          isCustom: customSort.has(menu.path)
        })
      })
    }
  })

  console.log('[菜单管理] 最终插件菜单列表:', pluginMenus)
  return pluginMenus
}

// 构建菜单树
const buildMenuTree = (menus: any[]) => {
  const menuMap = new Map()

  console.log('[菜单树] 开始构建菜单树，总菜单数:', menus.length)

  // 第一遍循环: 创建所有菜单的副本并放入 Map
  menus.forEach(menu => {
    const id = menu.ID || menu.id
    if (!id) {
      console.warn('[菜单树] 菜单缺少ID:', menu)
      return
    }

    // 创建菜单的深拷贝,避免修改原对象
    const menuCopy = {
      ...menu,
      children: []  // 每个菜单都有空的 children 数组
    }

    menuMap.set(id, menuCopy)

    console.log(`[菜单树] 添加菜单到 Map:`, {
      id,
      name: menu.name,
      isPlugin: menu.isPlugin,
      parentId: menu.parentId
    })
  })

  const tree: any[] = []

  // 第二遍循环: 构建树形结构
  menus.forEach(menu => {
    const id = menu.ID || menu.id
    const menuItem = menuMap.get(id)

    if (!menuItem) {
      console.warn('[菜单树] 找不到菜单:', menu)
      return
    }

    // 统一处理 parentId
    let parentId = menu.parentId

    // 对于系统菜单，如果 parentId 是 0，视为顶级菜单
    if (!menu.isPlugin && (!parentId || parentId === 0)) {
      parentId = null
    }

    console.log(`[菜单树] 处理菜单 ${menu.name}:`, {
      id,
      parentId,
      isPlugin: menu.isPlugin,
      hasParent: parentId && menuMap.has(parentId)
    })

    if (parentId && menuMap.has(parentId)) {
      // 有父菜单 - 将当前菜单添加到父菜单的 children
      const parent = menuMap.get(parentId)

      // 检查是否已经添加过(避免重复)
      if (!parent.children.includes(menuItem)) {
        parent.children.push(menuItem)
        console.log(`[菜单树] 将 ${menu.name} 添加到父菜单 ${parent.name}`)
      } else {
        console.warn(`[菜单树] ${menu.name} 已经在父菜单 ${parent.name} 的 children 中`)
      }
    } else if (parentId) {
      // parentId 存在但找不到对应的父菜单
      console.warn(`[菜单树] 找不到菜单 ${menu.name} 的父菜单 (parentId: ${parentId})`)
      // 作为顶级菜单处理
      if (!tree.includes(menuItem)) {
        tree.push(menuItem)
      }
    } else {
      // 顶级菜单
      if (!tree.includes(menuItem)) {
        tree.push(menuItem)
        console.log(`[菜单树] 将 ${menu.name} 作为顶级菜单`)
      } else {
        console.warn(`[菜单树] ${menu.name} 已经在顶级菜单中`)
      }
    }
  })

  // 对每层菜单按 sort 排序
  const sortMenus = (menus: any[]) => {
    menus.sort((a, b) => (a.sort || 0) - (b.sort || 0))
    menus.forEach(menu => {
      if (menu.children && menu.children.length > 0) {
        sortMenus(menu.children)
      }
    })
  }

  sortMenus(tree)

  console.log('[菜单树] 构建完成，顶级菜单数:', tree.length)
  console.log('[菜单树] 最终树结构:', tree)

  return tree
}

const loadMenus = async () => {
  loading.value = true
  try {
    // 清空现有菜单,避免重复
    menuList.value = []

    // 1. 获取系统菜单
    let systemMenus: any[] = []
    try {
      systemMenus = await getMenuTree() || []
      console.log('[菜单管理] 系统菜单:', systemMenus)
    } catch (error) {
      console.error('[菜单管理] 获取系统菜单失败:', error)
    }

    // 2. 获取插件菜单
    const pluginMenus = buildPluginMenuList()
    console.log('[菜单管理] 插件菜单:', pluginMenus)

    // 3. 合并菜单（展平系统菜单树）
    const flattenMenus = (menus: any[], result: any[] = []) => {
      menus.forEach(menu => {
        result.push(menu)
        if (menu.children && menu.children.length > 0) {
          flattenMenus(menu.children, result)
        }
      })
      return result
    }

    const flatSystemMenus = flattenMenus(systemMenus)
    const allMenus = [...flatSystemMenus, ...pluginMenus]

    console.log('[菜单管理] 合并后的所有菜单数:', allMenus.length)

    // 4. 重新构建菜单树
    menuList.value = buildMenuTree(allMenus)
    console.log('[菜单管理] 最终菜单树:', menuList.value)

    // 5. 构建菜单树选项（仅包含系统菜单，因为新建菜单时不应该在插件菜单下创建）
    menuTreeOptions.value = JSON.parse(JSON.stringify(systemMenus || []))
    menuTreeOptions.value.unshift({ ID: 0, name: '顶级菜单' })
  } finally {
    loading.value = false
  }
}

const handleAdd = () => {
  isEdit.value = false
  editingPluginMenu.value = false
  dialogTitle.value = '新增菜单'
  resetForm()
  dialogVisible.value = true
}

const handleEdit = (row: any) => {
  isEdit.value = true
  editingPluginMenu.value = false
  dialogTitle.value = '编辑菜单'
  // 正确处理ID字段，兼容大小写
  menuForm.id = row.ID || row.id
  menuForm.name = row.name
  menuForm.code = row.code
  menuForm.type = row.type
  menuForm.parentId = row.parentId === 0 ? 0 : (row.parentId || 0)
  menuForm.path = row.path
  menuForm.component = row.component
  menuForm.icon = row.icon
  menuForm.sort = row.sort
  menuForm.visible = row.visible
  menuForm.status = row.status
  dialogVisible.value = true
}

// 处理插件菜单排序编辑
const handleEditPluginSort = (row: any) => {
  isEdit.value = true
  editingPluginMenu.value = true
  dialogTitle.value = '调整插件菜单排序'

  // 填充表单数据
  menuForm.id = row.ID || row.id
  menuForm.name = row.name
  menuForm.code = row.code
  menuForm.type = row.type
  menuForm.parentId = row.parentId || 0
  menuForm.path = row.path
  menuForm.component = row.component || ''
  menuForm.icon = row.icon
  menuForm.sort = row.sort
  menuForm.visible = row.visible
  menuForm.status = row.status

  console.log('[菜单管理] 编辑插件菜单排序:', row)
  dialogVisible.value = true
}

const handleDelete = async (row: any) => {
  try {
    await ElMessageBox.confirm('确定要删除该菜单吗？', '提示', { type: 'warning' })
    await deleteMenu(row.ID || row.id)
    ElMessage.success('删除成功')
    loadMenus()
  } catch (error) {
    if (error !== 'cancel') console.error(error)
  }
}

const handleSubmit = async () => {
  if (!formRef.value) return
  await formRef.value.validate(async (valid) => {
    if (valid) {
      try {
        // 如果是编辑插件菜单，只保存排序到 localStorage
        if (editingPluginMenu.value) {
          const menuPath = menuForm.path
          const sort = menuForm.sort

          // 保存排序到 localStorage
          savePluginMenuSort(menuPath, sort)

          ElMessage.success(`插件菜单 "${menuForm.name}" 排序已更新`)
          dialogVisible.value = false
          resetForm()

          // 重新加载菜单以应用新的排序
          loadMenus()

          // 通知 Layout 刷新菜单
          window.dispatchEvent(new CustomEvent('plugins-changed'))
          return
        }

        // 系统菜单的正常处理流程
        const data = { ...menuForm }
        // 处理 parentId
        if (Array.isArray(data.parentId)) {
          const lastValue = data.parentId[data.parentId.length - 1]
          // 级联选择器返回的是数组，取最后一个值
          // 如果是空数组或者最后一项是null/undefined，设置为0（顶级菜单）
          data.parentId = (lastValue !== null && lastValue !== undefined) ? lastValue : 0
        }
        // 确保parentId是数字类型
        data.parentId = Number(data.parentId)

        console.log('提交的数据:', data)

        if (isEdit.value) {
          await updateMenu(menuForm.id, data)
        } else {
          await createMenu(data)
        }
        ElMessage.success('操作成功')
        dialogVisible.value = false
        // 重置表单
        resetForm()
        loadMenus()
      } catch (error) {
        console.error(error)
        ElMessage.error('操作失败')
      }
    }
  })
}

const resetForm = () => {
  editingPluginMenu.value = false
  Object.assign(menuForm, {
    id: 0,
    name: '',
    code: '',
    type: 2,
    parentId: 0,
    path: '',
    component: '',
    icon: '',
    sort: 0,
    visible: 1,
    status: 1
  })
  formRef.value?.clearValidate()
}

onMounted(() => {
  loadMenus()
})
</script>

<style scoped>
.menus-container {
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
