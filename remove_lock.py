#!/usr/bin/env python3
# 彻底删除 main.c 里所有锁屏残留代码
import re

with open('/home/ubuntu/Boss-tool-repo/main.c', 'r', encoding='utf-8') as f:
    content = f.read()

original_len = len(content.splitlines())
print(f"原始行数: {original_len}")

# ============================================================
# 1. 删除键盘钩子里的 if (g_bLocked) { ... } return 1; 块
#    这是导致 Win+L 闪烁的核心凶手：当 g_bLocked 意外为 TRUE 时
#    所有键盘事件都被吃掉，系统键盘完全失效
# ============================================================
lock_hook_pattern = r'    if \(g_bLocked\) \{.*?        return 1;\n    \}\n'
match = re.search(lock_hook_pattern, content, re.DOTALL)
if match:
    print(f"找到 g_bLocked 钩子块，行范围内容长度: {len(match.group())}")
    content = content[:match.start()] + '    /* v4.15: 锁屏功能已彻底删除，此处不再拦截任何键盘事件 */\n' + content[match.end():]
    print("✓ 已删除 g_bLocked 键盘钩子块")
else:
    print("✗ 未找到 g_bLocked 键盘钩子块，请检查")

# ============================================================
# 2. 删除锁屏界面代码块：
#    从 "/* ====...锁屏界面..." 注释开始
#    到 DoUnlockScreen 函数结束（最后一个 }）
#    LoginWndProc 之前停止
# ============================================================
lock_ui_pattern = r'/\* =+\s*\n\s*锁屏界面\s*\n\s*=+ \*/\n.*?(?=\n/\* =+\s*\n\s*登录对话框)'
match2 = re.search(lock_ui_pattern, content, re.DOTALL)
if match2:
    print(f"找到锁屏界面代码块，长度: {len(match2.group())} 字符")
    content = content[:match2.start()] + '/* v4.15: 锁屏界面代码已彻底删除 */\n\n' + content[match2.end():]
    print("✓ 已删除锁屏界面代码块")
else:
    print("✗ 未找到锁屏界面代码块，尝试备用方案")
    # 备用：直接按行号删除 2490-2886（GenLogLine到DoUnlockScreen结束）
    lines = content.splitlines(keepends=True)
    # 重新搜索精确行
    start_line = None
    end_line = None
    for i, line in enumerate(lines):
        if '锁屏界面' in line and i > 2400:
            start_line = i - 3  # 包含注释头
        if 'static void DoUnlockScreen(void) {' in line and start_line:
            # 找到函数体结束
            brace = 0
            for j in range(i, len(lines)):
                brace += lines[j].count('{') - lines[j].count('}')
                if brace <= 0 and j > i:
                    end_line = j + 1
                    break
            break
    if start_line and end_line:
        print(f"备用方案：删除行 {start_line+1} 到 {end_line+1}")
        del lines[start_line:end_line]
        content = ''.join(lines)
        print("✓ 备用方案成功")
    else:
        print(f"✗ 备用方案也失败: start={start_line}, end={end_line}")

# ============================================================
# 3. 删除全局变量里的锁屏状态变量
# ============================================================
lock_vars_pattern = r'/\* 锁屏状态 \*/\nstatic int.*?static WCHAR g_szLogBuf\[32\]\[160\];\nstatic int   g_nLogCount.*?= 0;\n'
match3 = re.search(lock_vars_pattern, content, re.DOTALL)
if match3:
    print(f"找到锁屏状态变量块")
    content = content[:match3.start()] + '/* v4.15: 锁屏状态变量已删除 */\n' + content[match3.end():]
    print("✓ 已删除锁屏状态变量")
else:
    print("✗ 未找到锁屏状态变量块（可能已删除）")

# ============================================================
# 4. 清理前向声明里的锁屏相关声明
# ============================================================
content = re.sub(r'LRESULT CALLBACK LockWndProc\(HWND, UINT, WPARAM, LPARAM\);\n', 
                 '/* v4.15: LockWndProc 已删除 */\n', content)
content = re.sub(r'static void DoLockScreen\(void\);\n', '', content)
content = re.sub(r'static void DoUnlockScreen\(void\);\n', '', content)
print("✓ 已清理前向声明")

# ============================================================
# 5. 清理全局变量里的 g_hWndLock 和 g_bLocked
# ============================================================
content = re.sub(r'static HWND\s+g_hWndLock\s+=\s+NULL;\n', 
                 '/* v4.15: g_hWndLock 已删除 */\n', content)
content = re.sub(r'static volatile BOOL g_bLocked\s+=\s+FALSE;\n',
                 '/* v4.15: g_bLocked 已删除 */\n', content)
print("✓ 已清理 g_hWndLock / g_bLocked 全局变量")

# ============================================================
# 6. 更新版本号
# ============================================================
content = content.replace('BossTool v4.14', 'BossTool v4.15')
content = content.replace('CONFIG_VERSION      10', 'CONFIG_VERSION      11')
print("✓ 版本号更新到 v4.15")

# 写回文件
with open('/home/ubuntu/Boss-tool-repo/main.c', 'w', encoding='utf-8') as f:
    f.write(content)

new_len = len(content.splitlines())
print(f"\n修改后行数: {new_len}（减少了 {original_len - new_len} 行）")
print("完成！")
