# CHANGELOG v4.2.1

> **核心：真正修复 `ERR_NO_BUFFER_SPACE`（WSAENOBUFS 10055）**

---

## 根因（这次终于找对了）

之前 v3.3.4 和 v4.0 的修复都是**治标不治本**。真正触发这个错误的是**两件事叠加**：

### 真凶 1：每次按老板键都自动 MAC 随机化
`SetIPBoss()` / `SetIPWork()` 里都自动调 `RandomizeMac()`，这个函数会：
1. `netsh interface set interface admin=disabled` （网卡禁用 1.5s）
2. `netsh interface set interface admin=enabled` （网卡启用 2s）

每次 disable/enable 网卡，Windows 会：
- 杀掉所有绑定到该网卡的 socket
- 重新初始化网络栈
- 重新分配内核 nonpaged pool

**反复 10 多次** → nonpaged pool 碎片化，但还没到阈值，**看不出问题**。
**用一阵子网络后**（几十个浏览器 tab、IM、Outlook），应用层占用了大量 socket 资源。
**下午再按一次老板键** → 又一次 disable/enable + 切 IP → socket 释放/重绑中，nonpaged pool 申请失败 → **`WSAENOBUFS 10055`**。

### 真凶 2：兜底快捷键（Ctrl+Alt+F12）"无效"
`netsh interface set interface name="..." admin=disabled` 在 **Windows 10 1903+ 已被微软废弃**。很多驱动（USB 网卡、Wi-Fi、Hyper-V 虚拟网卡）**直接忽略这条命令**。
所以紧急修复步骤 1 是 noop → 网卡没真正禁用 → 网络栈没真正重置 → 用户感觉"完全无效"。

---

## 修复

### 1. 去掉老板键的自动 MAC 随机化
**提交**：`fix(network): stop auto-randomizing MAC on every boss key`

- `SetIPBoss` / `SetIPWork` 不再调 `RandomizeMac()`
- MAC 随机化改用户手动从设置菜单触发（带警告对话框）
- 删除了 unused 的 `g_bEnableMacRandomization` 全局变量

### 2. 兜底修复改用 PowerShell `Disable-NetAdapter`
**提交**：`fix(network): use Disable-NetAdapter/Enable-NetAdapter in emergency fix`

- 改用 PowerShell cmdlet `Disable-NetAdapter` / `Enable-NetAdapter`（微软官方推荐 API）
- 对所有现代驱动（USB、Wi-Fi、Hyper-V 虚拟网卡）都生效
- 旧的 netsh 命令作为 fallback 保留
- 增强流程：`ipconfig /flushdns` + `route /f`（flush stale routes）

### 3. 设置窗口加"紧急恢复网络"按钮
**提交**：`feat(settings): add 'emergency network recovery' button`

- 新增 `IDC_SET_NETFIX` 按钮，明显大块带 `BS_DEFPUSHBUTTON` 粗框
- 标签：`☠ 紧急恢复网络 (Ctrl+Alt+F12)`，旁边带说明
- 点击后：弹"开始恢复"提示框 → 异步跑修复 → 完成后弹"修复完成"对话框（带 IP 检测结果）
- 跟快捷键的区别：按钮触发后弹完成提示；快捷键/IPGuard 自动触发保持静默

### 4. 设置窗口加"手动 MAC 随机化"按钮
**提交**：`feat(settings): add 'manual MAC randomize' button (off by default)`

- 新增 `IDC_SET_RANDMAC` 按钮，默认不跑
- 点击前弹警告对话框（解释会断网 3-5s、频繁用会触发网络问题）
- 异步跑 `RandomizeMac()`，UI 不冻结

---

## 升级方式

从 v4.1 直接覆盖 `BossTool.exe` 即可。配置（注册表）兼容。

注意：第一次启动时，IPGuard 检测到期望 IP 不在网卡上会**自动 Apply 一次**（这是正常行为，不是 bug）。等待 5-10 秒后 IP 会自动恢复。

---

## 验证清单

按 [RELEASE_PROCESS.md](RELEASE_PROCESS.md) 强制项：

- [ ] 老板键切换（连续 30 次）— 不应再触发 ERR_NO_BUFFER_SPACE
- [ ] 锁屏与解锁（密码输入、失败锁定）
- [ ] 紧急修复热键 Ctrl+Alt+F12（锁屏/非锁屏都测）— 应真正重置网络
- [ ] 设置窗口的"紧急恢复网络"按钮 — 弹完成对话框
- [ ] 设置窗口的"手动 MAC 随机化"按钮 — 弹警告 + 异步跑
- [ ] 网络切换后浏览器连通性验证（chrome / edge / firefox）

---

## 影响文件

- `main.c` — 主要改动

## 不影响

- 保险箱（VHDX/BitLocker）功能
- 锁屏（Ubuntu 伪装界面）功能
- 配置文件（注册表）schema
- 老板键、热键、键位设置
