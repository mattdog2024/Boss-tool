# BossTool v4.22 变更日志

## 修复：老板键触发后 Win 键卡死导致屏幕切换 / 无法输入文字

### 症状

用户按下老板键（默认 `Ctrl+Win+Alt+X`）后，出现以下异常：

1. 字符无法输入到任何应用窗口（包括记事本、浏览器、聊天软件等）
2. 屏幕在多个工作区/桌面之间来回切换
3. 类似"微软徽标键（Win 键）一直被按住"的现象

### 根因分析

`KeyboardHookProc`（main.c 第 2864 行附近，原 v4.16-v4.21 版本）中存在一个条件判断错误：

```c
if ((vk == VK_LWIN || vk == VK_RWIN) && s_bModCtrl && s_bModAlt) {
    return 1;  // 吃 Win 键事件（防开始菜单弹出）
}
```

这段代码的本意是：当三键（Ctrl+Win+Alt）同时按下触发老板键时，吃掉 Win 键事件防止开始菜单弹出。

**但条件中没有判断 `bDown`（按键按下方向）**，所以当用户完成三键操作后松开 Win 键时：

- Win 键的 **UP 事件**也被吃掉了
- Windows 内核状态机收不到 Win 键释放信号
- 系统认为 Win 键"一直被按着"
- 任何后续按下的键（包括普通字符 L、X 等）都会被 Windows 解析为"Win+L"（锁屏）、"Win+X"（系统菜单）、"Win+D"（显示桌面）等组合键
- 表现就是"屏幕疯狂切换"、"字符无法输入"

`v4.19` 引入的 5 秒超时自愈机制**只重置了本地的 `s_bMod*` 状态变量**，没有同步 Windows 内核的修饰键状态，因此即使本地状态恢复了，Windows 内核依然认为 Win 键被按着。

### 修复方案

v4.22 采用**双重保险**机制彻底解决：

#### 修复 1：钩子只吃 Win 键 DOWN 事件（最小侵入）

main.c 第 2912 行：

```c
if (bDown && (vk == VK_LWIN || vk == VK_RWIN) && s_bModCtrl && s_bModAlt) {
    /* 三键全部按着,吃 Win DOWN 防开始菜单 */
    return 1;
}
```

只吃 `bDown==TRUE` 的 Win DOWN 事件，**Win UP 事件必须放行让系统收到**，保证 Windows 内核能正常跟踪 Win 键释放。

#### 修复 2：DoBossKey 主动释放所有修饰键（强同步）

新增 `ReleaseAllModifiers()` 函数（main.c 第 2765 行），老板键触发瞬间主动用 `SendInput` 给系统补发 8 个修饰键的 KEYUP 事件：

```c
static void ReleaseAllModifiers(void) {
    static const WORD keys[] = {
        VK_LCONTROL, VK_RCONTROL,
        VK_LMENU,    VK_RMENU,
        VK_LSHIFT,   VK_RSHIFT,
        VK_LWIN,     VK_RWIN
    };
    INPUT inputs[8] = {0};
    UINT n = 0;
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        inputs[n].type           = INPUT_KEYBOARD;
        inputs[n].ki.wVk         = keys[i];
        inputs[n].ki.wScan       = 0;
        inputs[n].ki.dwFlags     = KEYEVENTF_KEYUP;
        inputs[n].ki.time        = 0;
        inputs[n].ki.dwExtraInfo = 0;
        n++;
    }
    if (n > 0) {
        SendInput(n, inputs, sizeof(INPUT));
    }
}
```

`DoBossKey()` 在启动后台线程前先调用此函数，**强制把 Windows 内核的修饰键状态同步为"全部已释放"**。

- 函数幂等：即使某些键并未按着，补发 KEYUP 等于"重新声明已释放"，无副作用
- 双重保险：即使将来钩子逻辑有其他 bug 导致修饰键状态错乱，老板键触发时也会强制同步

### 验证

- 编译验证：`x86_64-w64-mingw32-gcc -O2 -municode -mwindows` 零错误零警告
- 行为验证：触发老板键后立即可以正常输入字符，不再有屏幕切换

### 影响范围

- 修改文件：`main.c`（核心修复 + 注释更新）
- 新增函数：`ReleaseAllModifiers()`
- 修改函数：`DoBossKey()`, `KeyboardHookProc()`
- 无新增依赖，无需重新打包运行时
