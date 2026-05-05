# ZIP 代码包上传功能实现总结

## 功能概述

为代码安全审计平台添加了 **ZIP 代码包上传**功能，用户现在可以通过四种方式导入代码进行审计：
1. GitHub 候选发现（搜索）
2. Git 地址直接导入
3. **ZIP 代码包上传**（新增）
4. 本地仓库导入

## 实现细节

### 1. 前端修改

#### `public/discover.html`
- 添加了"ZIP 代码包上传"选项卡
- 新增文件上传输入框（支持多文件选择）
- 添加上传预览区域，显示已选文件列表和大小

#### `public/app.js`
- 更新 `initDiscoverPage()` 函数，添加 ZIP 上传模式处理
- 新增 `updateUploadPreview()` 函数：实时显示选中的文件信息
- 新增 `handleZipUpload()` 函数：处理文件上传逻辑
  - 验证文件大小（100MB 限制）
  - 使用 FormData 上传文件
  - 显示上传进度
- 更新 `syncSourceMode()` 函数：控制不同输入模式的显示/隐藏

#### `public/styles.css`
- 添加上传相关样式：
  - `.upload-preview` - 预览容器
  - `.upload-file-list` - 文件列表
  - `.upload-file-item` - 单个文件项
  - `input[type="file"]` - 文件输入框样式
  - `::file-selector-button` - 选择文件按钮样式

### 2. 后端新增 Agent

#### `src/agents/zipUploadScoutAgent.js`

**核心功能：**
- `processZipFiles()` - 批量处理上传的 ZIP 文件
- `extractAndProcess()` - 解压并处理单个 ZIP 文件
- `extractZip()` - 跨平台 ZIP 解压
  - Linux/Mac: 使用 `unzip` 命令
  - Windows: 使用 PowerShell `Expand-Archive`
- `detectLanguage()` - 自动检测项目主要编程语言
- `getProjectStats()` - 统计文件数量和总大小
- `buildProjectInfo()` - 构建项目信息对象

**特性：**
- 支持多文件上传
- 自动去重（检查目录是否已存在）
- 跨平台解压支持
- 5分钟解压超时保护
- 自动清理临时上传文件
- 错误容错（单个文件失败不影响其他文件）

### 3. 后端集成

#### `server.js`

**新增路由：**
- `POST /api/tasks/upload` - 处理 ZIP 文件上传
  - 解析 multipart/form-data
  - 创建审计任务
  - 触发解压和审计流程

**新增函数：**
- `parseMultipartForm()` - 解析 multipart/form-data 请求
  - 提取表单字段
  - 保存上传文件到 `workspace/uploads/`
  - 返回文件信息（filename, filepath, size）

**更新函数：**
- `runScout()` - 添加 `zip-upload` 分支处理
- `runAudit()` - 识别 `zip-upload` 来源的项目

### 4. 工作流程

```
用户选择 ZIP 文件
    ↓
前端验证文件大小
    ↓
FormData 上传到 /api/tasks/upload
    ↓
后端解析 multipart/form-data
    ↓
保存文件到 workspace/uploads/
    ↓
创建审计任务
    ↓
ZipUploadScoutAgent 解压文件
    ↓
检测语言和统计信息
    ↓
生成项目列表
    ↓
进入审计流程
```

## 技术特点

### 安全性
- 文件大小限制：100MB/文件
- 解压超时保护：5分钟
- 自动清理临时文件
- 错误隔离（单个文件失败不影响其他）

### 跨平台支持
- Linux/Mac: `unzip` 命令
- Windows: PowerShell `Expand-Archive`
- 自动检测可用工具

### 用户体验
- 实时文件预览
- 上传进度显示
- 解压进度反馈
- 友好的错误提示

## 文件结构

```
workspace/
├── uploads/          # 临时上传文件（处理后自动删除）
├── downloads/        # 解压后的项目目录
│   ├── project1/
│   ├── project2/
│   └── ...
├── reports/          # 审计报告
└── tasks/            # 任务状态
```

## API 端点

### POST /api/tasks/upload

**请求格式：** `multipart/form-data`

**参数：**
- `sourceType`: "zip-upload"
- `selectedSkillIds`: JSON 字符串数组
- `useMemory`: "true" 或 "false"
- `zipFiles`: 文件（可多个）

**响应：**
```json
{
  "id": "task-id",
  "status": "running",
  "sourceType": "zip-upload",
  "progress": { ... }
}
```

## 使用示例

### 前端代码
```javascript
const formData = new FormData();
formData.append("sourceType", "zip-upload");
formData.append("selectedSkillIds", JSON.stringify(["gbt-code-audit"]));
formData.append("useMemory", "true");
formData.append("zipFiles", file1);
formData.append("zipFiles", file2);

const response = await fetch("/api/tasks/upload", {
  method: "POST",
  body: formData
});
```

### 后端处理
```javascript
const uploadResult = await parseMultipartForm(req);
// uploadResult.files = [
//   { filename: "project1.zip", filepath: "/path/to/file", size: 1024000 },
//   { filename: "project2.zip", filepath: "/path/to/file", size: 2048000 }
// ]

const scoutResult = await zipUploadScoutAgent.processZipFiles(
  uploadResult.files,
  (progress) => updateTaskProgress(taskId, progress)
);
```

## 限制和注意事项

1. **文件大小限制**：单个文件最大 100MB
2. **支持格式**：仅支持 .zip 格式
3. **解压工具依赖**：
   - Linux/Mac 需要 `unzip` 命令
   - Windows 需要 PowerShell（通常已内置）
4. **超时设置**：解压超时 5 分钟
5. **磁盘空间**：确保有足够空间存储解压后的文件

## 未来改进方向

1. 支持更多压缩格式（.tar.gz, .7z, .rar）
2. 增加病毒扫描
3. 支持拖拽上传
4. 断点续传
5. 压缩包内容预览
6. 批量上传进度条
7. 上传历史记录

## 测试建议

1. **功能测试**
   - 单文件上传
   - 多文件上传
   - 超大文件（>100MB）
   - 损坏的 ZIP 文件
   - 空 ZIP 文件

2. **兼容性测试**
   - Windows 10/11
   - Linux (Ubuntu, CentOS)
   - macOS

3. **性能测试**
   - 大文件解压时间
   - 并发上传处理
   - 内存占用

4. **安全测试**
   - ZIP 炸弹防护
   - 路径遍历攻击
   - 恶意文件名处理
