# BossTool - 老板键工具

一键切换IP地址、MAC地址、清除系统痕迹的隐私保护工具（Windows 10/11）。

## 功能

- **老板键一键切换**：按快捷键在两个IP之间快速切换（约4-5秒完成）
- **自动更换MAC地址**：每次切换IP时随机更换网卡MAC地址
- **清除系统痕迹**：自动清理CMD历史、资源管理器地址栏、远程桌面记录等
- **锁屏保护**：内置密码锁屏功能，防止他人查看屏幕
- **记事本指示器**：切换到工作IP时自动打开记事本作为状态指示，切换回来时自动关闭
- **开机自动恢复**：重启后自动恢复到默认工作IP

## 文件说明

| 文件 | 说明 |
|------|------|
| `BossTool.exe` | 主程序（64位，Windows 10/11） |
| `BossTool_x86.exe` | 主程序（32位，Windows 7/8） |
| `FixACLUltimate.exe` | 注册表ACL修复工具（64位） |
| `FixACLUltimate_x86.exe` | 注册表ACL修复工具（32位） |
| `main.c` | 主程序源代码 |
| `fix_acl_ultimate.c` | 修复工具源代码 |

## 使用方法

1. 右键 `BossTool.exe` → 以管理员身份运行
2. 按老板键（Ctrl+Alt+X）在两个IP之间切换
3. 切换到老板IP时记事本自动弹出，切换回工作IP时记事本自动关闭

## 编译方法

需要 MinGW-w64 交叉编译工具链：

```bash
# 64位
x86_64-w64-mingw32-gcc -O2 -municode -mwindows -o BossTool.exe main.c \
    -lws2_32 -liphlpapi -ladvapi32 -lshell32 -lcomctl32 -lshlwapi -lole32 -static

# 32位
i686-w64-mingw32-gcc -O2 -municode -mwindows -o BossTool_x86.exe main.c \
    -lws2_32 -liphlpapi -ladvapi32 -lshell32 -lcomctl32 -lshlwapi -lole32 -static
```
