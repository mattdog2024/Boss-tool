# BossTool v3.3 变更日志

## 新功能：隐私保险箱（VHDX/BitLocker 伪装文件挂载）

### 功能说明

你可以把一个 `.vhdx` 文件改名为 `.lvm` 伪装成普通文件，并用 BitLocker 加密。
BossTool 会在老板键进入时自动挂载并解锁，退出时自动弹出并清除所有使用痕迹。

### 使用方法

1. 在设置界面（Ctrl+Alt+F10 → 输入密码）找到"隐私保险箱"区域
2. 点击"浏览..."选择你的 `.lvm` 伪装文件（实为 `.vhdx`）
3. 输入 BitLocker 密码
4. 点击"测试挂载"验证是否正常
5. 点击"保存并隐藏"保存配置
6. 之后每次按老板键（默认 Ctrl+Alt+X）进入老板模式时，自动挂载
7. 再次按老板键退出时，自动弹出并清除所有痕迹

### 修复的挂载失败问题

**问题根因（对照错误截图诊断）：**

| 问题 | 原因 | 修复方案 |
|------|------|----------|
| diskpart 退出码=0 但无盘符 | 脚本文件用 ANSI 编码，中文路径乱码，select vdisk 静默失败 | 改用 UTF-16 LE BOM 写入脚本文件 |
| BitLocker 解锁失败 | 挂载顺序错误（先解锁再挂载） | 先 attach vdisk 等盘符出现，再 manage-bde 解锁 |
| VDS 服务未运行 | Virtual Disk 服务未启动 | 挂载前自动检测并启动 Virtual Disk 服务 |

### 清理痕迹增强

退出老板模式时，除原有清理项外，新增：
- Chrome/Edge 浏览器历史记录
- 文件管理器快速访问列表（AutomaticDestinations）
- 跳转列表（JumpLists）
- 资源管理器地址栏历史

### 注意事项

1. **必须以管理员身份运行**（程序会自动请求提权）
2. **路径建议不含中文**（虽然已修复 UTF-16 编码，但 diskpart 在部分旧版 Windows 10 上仍可能有问题）
3. **需要 Virtual Disk 服务**：Win+R → services.msc → Virtual Disk → 启动类型改为"自动"
4. **BitLocker 密码**：保存在注册表中（XOR 混淆，非加密），请确保系统安全
