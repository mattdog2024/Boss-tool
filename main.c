/*
 * BossTool v4.19.2 - Windows 7/8/10/11 隱形管理工具
 *
 * v4.19.2 hotfix: 修复 BossToolKiller / BossToolForceExit 杀不掉老版本残留
 *   - 根因 1：ProtectProcess 设的 DACL 用 SetEntriesInAclW 插入 DENY Users，
 *     Windows 管理员默认也属于 Users 组，所以管理员的 OpenProcess 被
 *     DENY ACE 拒绝。SeDebugPrivilege 不能 bypass DENY ACE。
 *     修复：DACL 顺序改为 [ALLOW Administrators, DENY Users, 原 ACE...]。
 *   - 根因 2：v4.18 的"退出程序"按钮同步调用 SetIPWork（含 Sleep(2000)
 *     + 切换网卡），如果网络有问题阻塞主线程，永远到不了 DestroyWindow。
 *     修复：SetIPWork 改为 detached thread 异步执行，主线程立即 DestroyWindow。
 *   - 根因 3：BossToolKiller.c 之前没启用 SeDebugPrivilege。
 *     修复：加上 EnableDebugPrivilege()。
 *   - 根因 4：BossToolKiller.c 进程名只匹配 BossTool.exe / BossTool_x86.exe，
 *     没匹配 BossTool 进程伪装成的 audiodg.exe（v4.11+ 引入）。
 *     修复：匹配列表加上 audiodg.exe。
 *
 * v4.19.1 hotfix: 修复 v4.19 编译失败
 *   - v4.19 漏加 CleanupLockWorkstationPolicy 的前向声明，
 *     导致 IPGuardThread 在 CleanupLockWorkstationPolicy 定义之前
 *     调用它 → implicit declaration warning + linker error
 *   - 已在行 308-312 区域加 `static void CleanupLockWorkstationPolicy(void);`
 *
 * v4.19 修复 Win+L 锁屏后屏幕疯狂闪烁（根治）：
 *   - 根因（终于定位）：v4.16 修复不完整 + LL 钩子状态卡死
 *     1. 快速 Alt+Tab 切窗口时，Ctrl/Alt UP 事件可能被 Windows
 *        LowLevelHooksTimeout（默认 300ms）跳过，s_bModCtrl/s_bModAlt
 *        永远卡在 TRUE
 *     2. 下次按 Win+L 时，KeyboardHookProc 的 `(vk == VK_LWIN)
 *        && bCtrl && bAlt` 条件满足 → return 1 吃掉 Win 键
 *     3. 系统只收到 L 键，Win 键处于"按下但没收到对应 UP"状态
 *        → 开始菜单循环 → 屏幕疯狂闪烁 → 必须重启
 *   - 修复：
 *     1. 键盘钩子状态变量超时自愈：每个修饰键状态记录
 *        GetTickCount() 时间戳，超过 5 秒无对应 UP 事件视为卡死，
 *        自动重置状态变量。
 *     2. KeyboardHookProc 简化：移除 v4.9 的 bCtrl/bAlt/bWin
 *        局部副本不一致，统一直接使用 s_bModCtrl/s_bModAlt。
 *
 * v4.4 速度优化 + Win+L 联动：
 *   - 老板键切换从 ~20秒 优化到 <5秒：
 *     1. MAC随机化移至后台线程，不阻塞老板键响应
 *     2. 移除 ApplyIP 中重复的 ClearAccumulatedIPs 调用
 *        （SetIPBoss/SetIPWork 已调用过，无需重复）
 *     3. 减少所有 Sleep 等待时间（1500→800, 2000→1000, 500→200, 300→100）
 *   - Win+L 联动：按下时自动激活老板键 + 显示 Ubuntu 伪装锁屏
 *     一步到位，无需先按老板键再按锁屏
 *
 * v4.3 终极修复 ERR_NO_BUFFER_SPACE (WSAENOBUFS 10055)：
 *   - v4.2 只修了 IP 累积（表象），真正根因是非分页池耗尽：
 *     1. RandomizeMac 每次 disable/enable 网卡 → TCP/IP 栈完全重建
 *        → 消耗大量非分页池内存（NDIS buffer pools、ARP tables）
 *     2. 每次老板键切换 = 2次网卡周期（进+出）+ ~20-30个进程
 *        → 内核内存碎片化
 *     3. IPGuardThread 级联恢复：网卡刚重置还不稳定 → 发现"IP丢失"
 *        → 生成10-25个进程尝试恢复 → 更多压力 → 恶性循环
 *     4. EmergencyNetworkFix 绕过自旋锁（InterlockedExchange 强制设1）
 *        → 和正在执行的 SetIPBoss/SetIPWork 冲突 → 两次 disable/enable
 *        同时进行 → 双倍非分页池消耗
 *     5. 适配器名称缓存（g_szAdapter）在网卡重置后从不刷新
 *        → Windows 可能重命名适配器 → 后续 netsh 命令静默失败
 *     6. ExecPowerShellWithOutput 缓冲区只有 1024 字节
 *        → IP 多时截断 → ClearAccumulatedIPs 无法完全清理
 *     7. WriteLog 无锁 → 4个线程并发写日志 → 文件句柄竞争
 *   - 修复方案：
 *     1. RandomizeMac 增加 3 分钟冷却计时器（g_dwLastMacRandomizeTick）
 *        → 冷却期内跳过，避免反复禁用/启用网卡
 *     2. ExecPowerShellWithOutput 缓冲区 1024 → 16384
 *        → 确保 ClearAccumulatedIPs 能读到所有IP
 *     3. RandomizeMac/EmergencyNetworkFix 后使 g_szAdapter[0]=0
 *        → 下次 GetAdapterName() 重新枚举，获取最新名称
 *     4. WriteLog 增加 CRITICAL_SECTION 互斥锁
 *        → 防止多线程并发写日志导致句柄泄漏
 *     5. EmergencyNetworkFix 改用 BeginNetworkChange() 正确获取锁
 *        → 不再绕过自旋锁，防止和 SetIPBoss/SetIPWork 冲突
 *     6. IPGuardThread 增加 60 秒冷却（g_dwLastNetworkResetTick）
 *        → 网卡重置后 60 秒内不触发恢复，避免级联崩溃
 *     7. EmergencyNetworkFix 也记录时间戳并使适配器缓存失效
 *
 * v4.2 修复 IP 累积（部分有效，但不足以解决问题）：
 *   - 新增 ClearAccumulatedIPs()、第二IP先删后加、增大检查间隔
 *
 * v3.3 新增：隐私保险箱（VHDX/BitLocker 伪装文件挂载）
 *   - 支持选择 .lvm（实为 .vhdx）伪装文件
 *   - 输入 BitLocker 密码，保存加密存储
 *   - 老板键进入时自动挂载 → 老板键退出时自动弹出并清理痕迹
 *   - 修复挂载失败根因：
 *     1. diskpart 脚本用 UTF-16 LE BOM 写入，解决中文路径乱码
 *     2. 先 attach vdisk，等盘符出现，再 manage-bde 解锁
 *     3. 启动 Virtual Disk 服务检测
 *     4. 弹出时先 manage-bde -lock，再 detach vdisk
 *
 * v3.3.4 第一次尝试修复 ERR_NO_BUFFER_SPACE（不完全）：
 *   - 识别了 IP 累积是根因，但 v4.0 改为只 set 不 delete
 *   - 第二IP仍然只 add 不 delete，累积问题并未彻底解决
 *
 * v3.2 原始尝试（不完全）：
 *   - 重写 ApplyIP，改用 store=active
 *   - WatchdogThread Sleep 400→2000
 *   - g_bLocked / g_bBossMode 改用 InterlockedExchange
 *   - 新增 Ctrl+Alt+F12 一键修复网络栈热键
 */

#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <commctrl.h>
#include <winreg.h>
#include <aclapi.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ============================================================
   常量
   ============================================================ */
#define APP_MUTEX_NAME      L"Global\\WinSvcHostMutex_7F3A"
#define CONFIG_REG_KEY      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinSvcHost"
#define AUTORUN_REG_KEY     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define AUTORUN_VALUE_NAME  L"WinSvcHost"

#define DEFAULT_LOGIN_PWD   L"ccisme520"
#define DEFAULT_LOCK_PWD    L"6142234"
#define DEFAULT_BOSS_MOD    (MOD_CONTROL|MOD_WIN|MOD_ALT)
#define DEFAULT_BOSS_VK     'X'
#define CONFIG_VERSION      16   /* v4.19.2: 修复 BossToolKiller/ForceExit 杀不掉残留 + DACL 拒绝管理员 */
#define SETTINGS_MOD        (MOD_CONTROL|MOD_ALT)
#define SETTINGS_VK         VK_F10

/* 工作IP */
#define IP_WORK1        L"20.65.32.199"
#define IP_WORK2        L"192.168.1.88"
#define IP_WORK_MASK    L"255.255.255.0"
#define IP_WORK_GW      L"20.65.32.254"
#define IP_WORK_DNS     L"10.8.8.1"

/* 老板IP */
#define IP_BOSS         L"8.2.24.169"
#define IP_BOSS_MASK    L"255.255.252.0"
#define IP_BOSS_GW      L"8.2.27.254"
#define IP_BOSS_DNS     L"8.2.27.254"

/* 热键ID */
#define HOTKEY_BOSS       1001
#define HOTKEY_SETTINGS   1002
#define HOTKEY_NETFIX     1003
#define HOTKEY_NETFIX_ALT 1004
/* v4.19: HOTKEY_LOCK 已删除（v4.13 锁屏功能移除后的残留宏） */

#define EMERGENCY_MOD     (MOD_CONTROL|MOD_ALT)
#define EMERGENCY_VK      VK_F12
#define EMERGENCY_MOD_ALT (MOD_CONTROL|MOD_SHIFT)
#define EMERGENCY_VK_ALT  VK_F12

/* v4.19: LOCK_MOD / LOCK_VK 已删除（v4.13 锁屏功能移除后的残留宏） */

/* 自定义消息 */
#define WM_SHOW_SETTINGS (WM_USER+13)
#define WM_BOSS_KEY      (WM_USER+14)  /* v4.4: Win+L 联动老板键 */
/* v4.19: WM_LOCK_SCREEN / WM_TRAY_ICON 已删除 */
/* v4.19: IDM_TRAY_SETTINGS/BOSS/NETFIX/EXIT 已删除（托盘图标从未添加） */

/* 控件ID */
#define IDC_LOGIN_PWD    2001
#define IDC_LOGIN_OK     2002
#define IDC_LOGIN_CANCEL 2003

#define IDC_SET_VPWD     3001
#define IDC_SET_VBTN     3002
#define IDC_SET_LPWD     3003
#define IDC_SET_SPWD     3004
#define IDC_SET_BMOD     3005
#define IDC_SET_BVK      3006
#define IDC_SET_AR       3007
#define IDC_SET_HL       3008
#define IDC_SET_SAVE     3009
#define IDC_SET_CLOSE    3010
#define IDC_SET_APPLYIP  3011
#define IDC_SET_EXIT     3013  /* v4.18: 退出程序 */
#define IDC_SET_ALLOWIP  3012

/* v3.3: 隐私保险箱控件ID */
#define IDC_VAULT_PATH      4001   /* .lvm 文件路径编辑框 */
#define IDC_VAULT_BROWSE    4002   /* 浏览按钮 */
#define IDC_VAULT_PWD       4003   /* BitLocker 密码编辑框 */
#define IDC_VAULT_TEST      4004   /* 测试挂载按钮 */
#define IDC_VAULT_EJECT     4005   /* 手动弹出按钮 */
#define IDC_VAULT_LABEL     4006   /* 分组标签 */

/* ============================================================
   全局变量
   ============================================================ */
static HINSTANCE g_hInst        = NULL;
static HWND      g_hWndMain     = NULL;
static HWND      g_hWndSettings = NULL;
/* v4.15: g_hWndLock 已删除 */
static HWND      g_hWndLogin    = NULL;
static HHOOK     g_hKeyHook     = NULL;
static HANDLE    g_hMutex       = NULL;

/* 状态标志 */
static volatile BOOL g_bBossMode = FALSE;
/* v4.15: g_bLocked 已删除 */
static volatile LONG g_lNetworkChangeBusy = 0;
static volatile LONG g_lEmergencyFixBusy  = 0;
static volatile BOOL g_bEnableMacRandomization = TRUE;  /* 每次切换IP时自动随机更换MAC地址 */

/* v4.3: 网卡操作冷却计时 — 防止反复禁用/启用网卡耗尽非分页池
 * 每次 RandomizeMac 执行后记录时间戳，后续调用若在冷却期内则跳过。
 * 这是修复 ERR_NO_BUFFER_SPACE 的核心：每次 disable/enable 网卡会
 * 导致 Windows TCP/IP 栈完全重建，消耗大量非分页池内存。
 * 3分钟内不重复操作，给系统足够时间回收资源。 */
static volatile LONG g_dwLastMacRandomizeTick = 0;
#define MAC_COOLDOWN_MS (180 * 1000)  /* 3分钟冷却 */

/* v4.3: IPGuard 冷却 — RandomizeMac 后60秒内不触发IP恢复 */
static volatile LONG g_dwLastNetworkResetTick = 0;
#define IPGUARD_COOLDOWN_MS (60 * 1000)  /* 60秒冷却 */

/* v4.9: 纯修饰键组合（Ctrl+Win+Alt）触发状态
 * 使用局部状态变量跟踪修饰键，而不依赖 GetAsyncKeyState。
 * 原因：在低级键盘钩子回调中，GetAsyncKeyState 可能存在时序问题，
 * 尤其是 Alt 键（触发 WM_SYSKEYDOWN）按下时可能还没有更新。 */
static volatile BOOL s_bBossComboTriggered = FALSE;
static volatile BOOL s_bModCtrl = FALSE;  /* Ctrl 键当前状态 */
static volatile BOOL s_bModWin  = FALSE;  /* Win  键当前状态 */
static volatile BOOL s_bModAlt  = FALSE;  /* Alt  键当前状态 */

/* v4.19: 修饰键状态时间戳 — 防止 LL 钩子超时导致状态卡住
 *
 * 背景：WH_KEYBOARD_LL 钩子如果在 LowLevelHooksTimeout（默认 300ms）
 * 内没返回，Windows 会强制跳过该次钩子调用，相应按键事件不会被钩子处理。
 * 在用户快速 Alt+Tab / Alt+Esc 切换窗口，或系统繁忙时，Ctrl/Alt 的 UP
 * 事件可能被跳过，导致 s_bModCtrl/s_bModAlt 永远卡在 TRUE。
 *
 * 后果：下次按 Win+L 时，KeyboardHookProc 行 2472 的
 *      `(vk == VK_LWIN) && bCtrl && bAlt` 条件满足 → return 1 吃掉
 *      Win 键 → 系统只收到 L 键 → Win 键卡死状态触发开始菜单循环 →
 *      屏幕疯狂闪烁。
 *
 * 修复：每次状态变量更新时记录 GetTickCount() 时间戳。
 *      钩子入口检查时间戳，超过 MOD_STALE_MS（5秒）无对应 UP 事件
 *      视为状态卡死，自动重置。 */
static volatile DWORD s_dwModCtrlTime = 0;
static volatile DWORD s_dwModAltTime  = 0;
static volatile DWORD s_dwModWinTime  = 0;
#define MOD_STALE_MS  5000  /* 5秒无对应UP事件视为状态卡死 */

/* v4.19: 键盘钩子诊断日志开关
 *
 * 设置环境变量 BOSS_KEYHOOK_DEBUG=1 启用详细日志：
 *   set BOSS_KEYHOOK_DEBUG=1
 *   BossTool.exe
 *
 * 启用后会写以下事件到 %TEMP%\bosstool.log：
 *   - 修饰键状态变化（Ctrl/Alt/Win DOWN/UP）
 *   - 老板键触发瞬间（带时间戳）
 *   - 状态超时自愈触发（带超时秒数）
 *   - 吃 Win 键的瞬间（带原因）
 *   - 钩子被 Windows 跳过（nCode < 0）次数
 *
 * 默认关闭以避免性能开销（WriteLog 涉及文件 I/O）。
 * 如果再次出现 Win+L 闪烁问题，请启用此开关重现并把日志发给开发者。 */
static volatile BOOL g_bHookDebug = FALSE;
static volatile DWORD s_dwHookSkipCount = 0;  /* 钩子被跳过的累计次数 */

/* v4.3: WriteLog 线程安全锁 — WatchdogThread/GuardThread/IPGuardThread/BossKeyThread
 * 都并发调用 WriteLog，无锁时多个线程同时 CreateFile/WriteFile 会导致
 * 文件句柄泄漏和缓冲区竞争，增加内核对象压力。 */
static CRITICAL_SECTION g_csLog;
static volatile BOOL g_bLogInitialized = FALSE;

/* 配置 */
static WCHAR g_szLoginPwd[64]   = DEFAULT_LOGIN_PWD;
static WCHAR g_szLockPwd[64]    = DEFAULT_LOCK_PWD;
static UINT  g_BossMod          = DEFAULT_BOSS_MOD;
static UINT  g_BossVk           = DEFAULT_BOSS_VK;
static BOOL  g_bAutoRun         = FALSE;
static WCHAR g_szHideList[2048] = L"";

/* v3.3: 隐私保险箱配置 */
static WCHAR g_szVaultPath[MAX_PATH]    = L"";   /* .lvm 文件路径 */
static WCHAR g_szVaultPwd[128]          = L"";   /* BitLocker 密码（内存中明文，注册表中 XOR 混淆） */
static WCHAR g_szVaultDrive[4]          = L"";   /* 当前挂载的盘符，如 L"E:" */
static WCHAR g_szVaultSymlink[MAX_PATH] = L"";   /* 临时符号链接路径（.vhdx 扩展名） */
static volatile BOOL g_bVaultMounted    = FALSE; /* 是否已挂载 */

/* v4.15: 锁屏状态变量已删除 */

/* 适配器名称缓存 */
static WCHAR g_szAdapter[256]   = {0};

/* IP守护 */
static volatile BOOL g_bIPGuardEnabled = FALSE;
static volatile BOOL g_bAllowIPChange = FALSE;
static WCHAR g_szExpectedIP[64] = {0};

/* 隐藏的窗口列表 */
#define MAX_HIDDEN_WNDS 64
static HWND  g_hiddenWnds[MAX_HIDDEN_WNDS];
static int   g_nHiddenWnds = 0;

/* ============================================================
   前向声明
   ============================================================ */
LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK LoginWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SettingsWndProc(HWND, UINT, WPARAM, LPARAM);
/* v4.15: LockWndProc 已删除 */
LRESULT CALLBACK KeyboardHookProc(int, WPARAM, LPARAM);
/* v4.13: WatchdogThread/GuardThread 已删除 */
DWORD WINAPI     IPGuardThread(LPVOID);
DWORD WINAPI     BossKeyThread(LPVOID);
static DWORD WINAPI VaultEjectThread(LPVOID);
DWORD WINAPI     InitialIPThread(LPVOID);
DWORD WINAPI     EmergencyFixThread(LPVOID);
/* v4.19: CleanupLockWorkstationPolicy 前向声明
 * IPGuardThread 在 CleanupLockWorkstationPolicy 定义之前调用它，
 * 需要先声明（C90 implicit declaration 在 MinGW 严格模式下会报错）。 */
static void     CleanupLockWorkstationPolicy(void);

static void DoBossKey(void);
static void ApplyIP(const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*);
static void LockIPReg(void);
static void ShowSettingsWindow(void);
static void ShowLoginDialog(void);
static void WriteLog(const WCHAR *fmt, ...);
static DWORD RunNetshDirect(const WCHAR *args);
static const WCHAR* GetAdapterName(void);
static void RandomizeMac(void);
static void ExecPowerShell(const WCHAR *psScript, BOOL bWait, DWORD timeoutMs);
static BOOL BeginNetworkChange(void);
static void EndNetworkChange(void);
static void StartDetachedThread(LPTHREAD_START_ROUTINE proc, LPVOID param);
static void EmergencyNetworkFix(void);
static void ClearAccumulatedIPs(void);

/* v3.3: 保险箱函数前向声明 */
static BOOL  VaultMount(HWND hWndParent);
static BOOL  VaultEject(HWND hWndParent);
static void  VaultAutoMount(void);
static void  VaultAutoEject(void);
static void  VaultRecoverAndEject(void);  /* v3.5: 启动时卸载旧版遗留的VHDX */
static void  SaveVaultConfig(void);
static void  LoadVaultConfig(void);
static WCHAR FindNewDriveLetter(DWORD dwBefore);
static DWORD GetAllDrives(void);
static BOOL  EnsureVirtualDiskService(void);
static BOOL  WaitForDriveLetter(DWORD dwBefore, WCHAR *pDrive, DWORD timeoutMs);
static BOOL  CreateVaultSymlink(void);    /* 创建 .vhdx 符号链接 */
static void  CleanupVaultSymlink(void);   /* 删除符号链接 */
static BOOL  ExecPowerShellWithOutput(const WCHAR *psScript, WCHAR *outBuf, int outLen); /* 执行 PS 并返回输出 */
static BOOL  GetDriveLetterForImage(const WCHAR *imagePath, WCHAR *pDrive); /* 通过 PS 查询盘符 */

/* ============================================================
   工具：后台无窗口执行命令（带返回值）
   ============================================================ */
static DWORD ExecHiddenEx(const WCHAR *cmd) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR buf[4096];
    WCHAR szComSpec[MAX_PATH] = {0};
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!GetEnvironmentVariableW(L"COMSPEC", szComSpec, MAX_PATH)) {
        GetSystemDirectoryW(szComSpec, MAX_PATH);
        wcsncat(szComSpec, L"\\cmd.exe", MAX_PATH - wcslen(szComSpec) - 1);
    }
    _snwprintf(buf, 4095, L"\"%ls\" /c %ls", szComSpec, cmd);
    buf[4095] = 0;
    DWORD exitCode = 0;
    if (CreateProcessW(NULL, buf, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return exitCode;
}

static void ExecHidden(const WCHAR *cmd) {
    ExecHiddenEx(cmd);
}

/* 异步执行（不等待） */
static void ExecAsync(const WCHAR *cmd) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR buf[4096];
    WCHAR szComSpec[MAX_PATH] = {0};
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (!GetEnvironmentVariableW(L"COMSPEC", szComSpec, MAX_PATH)) {
        GetSystemDirectoryW(szComSpec, MAX_PATH);
        wcsncat(szComSpec, L"\\cmd.exe", MAX_PATH - wcslen(szComSpec) - 1);
    }
    _snwprintf(buf, 4095, L"\"%ls\" /c %ls", szComSpec, cmd);
    buf[4095] = 0;
    if (CreateProcessW(NULL, buf, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* 直接调用 PowerShell.exe */
static void ExecPowerShell(const WCHAR *psScript, BOOL bWait, DWORD timeoutMs) {
    WCHAR szPS[MAX_PATH] = {0};
    GetSystemDirectoryW(szPS, MAX_PATH);
    wcsncat(szPS, L"\\WindowsPowerShell\\v1.0\\powershell.exe",
            MAX_PATH - wcslen(szPS) - 1);
    if (GetFileAttributesW(szPS) == INVALID_FILE_ATTRIBUTES) {
        WCHAR szWin[MAX_PATH] = {0};
        GetWindowsDirectoryW(szWin, MAX_PATH);
        _snwprintf(szPS, MAX_PATH-1,
            L"%ls\\SysNative\\WindowsPowerShell\\v1.0\\powershell.exe", szWin);
    }
    WCHAR cmdLine[4096];
    _snwprintf(cmdLine, 4095,
        L"\"%ls\" -NoProfile -NonInteractive -WindowStyle Hidden -Command \"%ls\"",
        szPS, psScript);
    cmdLine[4095] = 0;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    WriteLog(L"ExecPowerShell: %ls", cmdLine);
    if (!CreateProcessW(szPS, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WriteLog(L"ExecPowerShell: CreateProcess FAILED err=%lu", GetLastError());
        return;
    }
    if (bWait) {
        WaitForSingleObject(pi.hProcess, timeoutMs);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        WriteLog(L"ExecPowerShell: exit=%lu", exitCode);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

static BOOL BeginNetworkChange(void) {
    for (int i = 0; i < 240; i++) {
        if (InterlockedCompareExchange(&g_lNetworkChangeBusy, 1, 0) == 0)
            return TRUE;
        Sleep(500);
    }
    return FALSE;
}

static void EndNetworkChange(void) {
    InterlockedExchange(&g_lNetworkChangeBusy, 0);
}

static void StartDetachedThread(LPTHREAD_START_ROUTINE proc, LPVOID param) {
    HANDLE hThread = CreateThread(NULL, 0, proc, param, 0, NULL);
    if (hThread) CloseHandle(hThread);
}

/* ============================================================
   WriteLog（调试日志，写到 %TEMP%\bosstool.log）
   ============================================================ */
static void WriteLog(const WCHAR *fmt, ...) {
    /* v4.3: 加锁保护 — 多线程并发写日志会导致文件句柄竞争 */
    if (!g_bLogInitialized) {
        InitializeCriticalSection(&g_csLog);
        g_bLogInitialized = TRUE;
    }
    EnterCriticalSection(&g_csLog);

    WCHAR buf[1024];
    va_list va;
    va_start(va, fmt);
    _vsnwprintf(buf, 1023, fmt, va);
    buf[1023] = 0;
    va_end(va);

    WCHAR szPath[MAX_PATH];
    GetTempPathW(MAX_PATH, szPath);
    wcsncat(szPath, L"bosstool.log", MAX_PATH - wcslen(szPath) - 1);

    HANDLE hFile = CreateFileW(szPath, GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        SYSTEMTIME st; GetLocalTime(&st);
        WCHAR line[1200];
        _snwprintf(line, 1199, L"[%02d:%02d:%02d] %ls\r\n",
                   st.wHour, st.wMinute, st.wSecond, buf);
        line[1199] = 0;
        DWORD written;
        WriteFile(hFile, line, (DWORD)(wcslen(line)*sizeof(WCHAR)), &written, NULL);
        CloseHandle(hFile);
    }

    LeaveCriticalSection(&g_csLog);
}

/* ============================================================
   v3.3: 隐私保险箱 —— 核心实现
   ============================================================ */

/* 获取当前所有已挂载盘符的位掩码（bit0=A, bit1=B, bit2=C, ...) */
static DWORD GetAllDrives(void) {
    return GetLogicalDrives();
}

/* 等待新盘符出现，返回盘符字母（如 L'E'），超时返回 0 */
static BOOL WaitForDriveLetter(DWORD dwBefore, WCHAR *pDrive, DWORD timeoutMs) {
    DWORD elapsed = 0;
    while (elapsed < timeoutMs) {
        Sleep(500);
        elapsed += 500;
        DWORD dwNow = GetAllDrives();
        DWORD diff = dwNow & ~dwBefore;
        if (diff) {
            /* 找到新出现的盘符 */
            for (int i = 2; i < 26; i++) {  /* 从 C 开始 */
                if (diff & (1u << i)) {
                    *pDrive = (WCHAR)(L'A' + i);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/* 确保 Virtual Disk 服务已启动 */
static BOOL EnsureVirtualDiskService(void) {
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return FALSE;

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"vds", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hSvc) {
        /* 尝试 "Virtual Disk" 服务名 */
        hSvc = OpenServiceW(hSCM, L"vdsldr", SERVICE_QUERY_STATUS | SERVICE_START);
    }
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        /* 服务不存在也没关系，diskpart 会自动启动它 */
        return TRUE;
    }

    SERVICE_STATUS ss;
    QueryServiceStatus(hSvc, &ss);
    if (ss.dwCurrentState != SERVICE_RUNNING) {
        StartService(hSvc, 0, NULL);
        Sleep(1500);
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return TRUE;
}

/*
 * v3.3.3: 创建符号链接
 * AppHider 的核心秘诀：把 .lvm 文件符号链接为 .vhdx 扩展名
 * Mount-DiskImage 必须有 .vhdx/.iso 扩展名才能挂载
 */
static BOOL CreateVaultSymlink(void) {
    if (!g_szVaultPath[0]) return FALSE;

    /* 生成唯一符号链接路径：%TEMP%\BossVault_XXXX.vhdx */
    WCHAR szTemp[MAX_PATH];
    GetTempPathW(MAX_PATH, szTemp);
    WCHAR szGuid[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snwprintf(szGuid, 63, L"BossVault_%04d%02d%02d%02d%02d%02d%03d.vhdx",
               st.wYear, st.wMonth, st.wDay,
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    _snwprintf(g_szVaultSymlink, MAX_PATH-1, L"%ls%ls", szTemp, szGuid);
    g_szVaultSymlink[MAX_PATH-1] = 0;

    /* 先删除可能存在的旧符号链接 */
    DeleteFileW(g_szVaultSymlink);

    /* 用 PowerShell New-Item -ItemType SymbolicLink 创建
     * 注：创建符号链接需要管理员权限或开发者模式
     * 备用：用 cmd mklink
     */
    WCHAR szPS[MAX_PATH * 2 + 128];
    _snwprintf(szPS, MAX_PATH*2+127,
        L"New-Item -ItemType SymbolicLink -Path '%ls' -Target '%ls' -Force",
        g_szVaultSymlink, g_szVaultPath);
    szPS[MAX_PATH*2+127] = 0;

    ExecPowerShell(szPS, TRUE, 5000);

    /* 检查符号链接是否创建成功 */
    if (GetFileAttributesW(g_szVaultSymlink) != INVALID_FILE_ATTRIBUTES) {
        WriteLog(L"CreateVaultSymlink: 成功 [%ls] -> [%ls]", g_szVaultSymlink, g_szVaultPath);
        return TRUE;
    }

    /* PowerShell 失败，尝试 cmd mklink */
    WriteLog(L"CreateVaultSymlink: PowerShell 失败，尝试 cmd mklink");
    WCHAR szCmd[MAX_PATH * 2 + 64];
    _snwprintf(szCmd, MAX_PATH*2+63,
        L"cmd /c mklink \"%ls\" \"%ls\"",
        g_szVaultSymlink, g_szVaultPath);
    szCmd[MAX_PATH*2+63] = 0;
    ExecHiddenEx(szCmd);

    if (GetFileAttributesW(g_szVaultSymlink) != INVALID_FILE_ATTRIBUTES) {
        WriteLog(L"CreateVaultSymlink: mklink 成功");
        return TRUE;
    }

    WriteLog(L"CreateVaultSymlink: 失败，无法创建符号链接");
    g_szVaultSymlink[0] = 0;
    return FALSE;
}

/* 删除符号链接 */
static void CleanupVaultSymlink(void) {
    if (g_szVaultSymlink[0]) {
        DeleteFileW(g_szVaultSymlink);
        WriteLog(L"CleanupVaultSymlink: 删除 [%ls]", g_szVaultSymlink);
        g_szVaultSymlink[0] = 0;
    }
}

/* 执行 PowerShell 并返回标准输出 */
static BOOL ExecPowerShellWithOutput(const WCHAR *psScript, WCHAR *outBuf, int outLen) {
    if (outBuf && outLen > 0) outBuf[0] = 0;

    WCHAR szPS[MAX_PATH] = {0};
    GetSystemDirectoryW(szPS, MAX_PATH);
    wcsncat(szPS, L"\\WindowsPowerShell\\v1.0\\powershell.exe",
            MAX_PATH - wcslen(szPS) - 1);
    if (GetFileAttributesW(szPS) == INVALID_FILE_ATTRIBUTES) {
        WCHAR szWin[MAX_PATH] = {0};
        GetWindowsDirectoryW(szWin, MAX_PATH);
        _snwprintf(szPS, MAX_PATH-1,
            L"%ls\\SysNative\\WindowsPowerShell\\v1.0\\powershell.exe", szWin);
    }

    WCHAR cmdLine[4096];
    _snwprintf(cmdLine, 4095,
        L"\"%ls\" -NoProfile -NonInteractive -WindowStyle Hidden -Command \"%ls\"",
        szPS, psScript);
    cmdLine[4095] = 0;

    /* 创建匿名管道读取输出 */
    HANDLE hReadPipe = NULL, hWritePipe = NULL;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return FALSE;
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;

    BOOL ok = CreateProcessW(szPS, cmdLine, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(hWritePipe);

    if (!ok) {
        CloseHandle(hReadPipe);
        return FALSE;
    }

    /* 读取输出（ANSI）
     * v4.3: 缓冲区从 1024 扩大到 16384。
     * 当适配器上累积了大量IP时，PowerShell 输出可能超过 1024 字节，
     * 导致 ClearAccumulatedIPs 只能读到部分IP，无法完全清理。 */
    char ansiOut[16384] = {0};
    DWORD bytesRead = 0, totalRead = 0;
    while (totalRead < (DWORD)sizeof(ansiOut)-1) {
        DWORD avail = 0;
        if (!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &avail, NULL) || avail == 0) {
            if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) break;
            continue;
        }
        if (!ReadFile(hReadPipe, ansiOut + totalRead,
                      min(avail, (DWORD)sizeof(ansiOut)-1-totalRead),
                      &bytesRead, NULL)) break;
        totalRead += bytesRead;
    }
    ansiOut[totalRead] = 0;

    WaitForSingleObject(pi.hProcess, 5000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    /* 转换输出到宽字符 */
    if (outBuf && outLen > 0) {
        MultiByteToWideChar(CP_ACP, 0, ansiOut, -1, outBuf, outLen);
        /* 去除首尾空白 */
        int n = (int)wcslen(outBuf);
        while (n > 0 && (outBuf[n-1] == L'\r' || outBuf[n-1] == L'\n' ||
                         outBuf[n-1] == L' ')) {
            outBuf[--n] = 0;
        }
    }

    WriteLog(L"ExecPSWithOutput: exit=%lu out=[%ls]", exitCode, outBuf ? outBuf : L"");
    return (exitCode == 0);
}

/* 通过 PowerShell 查询已挂载镜像的盘符字母
 * 使用 AppHider 相同的命令：
 * Get-DiskImage -ImagePath '...' | Get-Disk | Get-Partition | Get-Volume |
 *   Select-Object -ExpandProperty DriveLetter
 */
static BOOL GetDriveLetterForImage(const WCHAR *imagePath, WCHAR *pDrive) {
    *pDrive = 0;
    WCHAR szPS[MAX_PATH + 256];
    _snwprintf(szPS, MAX_PATH+255,
        L"Get-DiskImage -ImagePath '%ls' | "
        L"Get-Disk | Get-Partition | Get-Volume | "
        L"Select-Object -ExpandProperty DriveLetter",
        imagePath);
    szPS[MAX_PATH+255] = 0;

    WCHAR outBuf[32] = {0};
    ExecPowerShellWithOutput(szPS, outBuf, 31);

    /* 输出应该是单个字母，如 "E" */
    if (outBuf[0] >= L'A' && outBuf[0] <= L'Z') {
        *pDrive = outBuf[0];
        WriteLog(L"GetDriveLetterForImage: 盘符=%lc", *pDrive);
        return TRUE;
    }
    if (outBuf[0] >= L'a' && outBuf[0] <= L'z') {
        *pDrive = (WCHAR)(outBuf[0] - L'a' + L'A');
        WriteLog(L"GetDriveLetterForImage: 盘符=%lc", *pDrive);
        return TRUE;
    }
    WriteLog(L"GetDriveLetterForImage: 未能获取盘符，输出=[%ls]", outBuf);
    return FALSE;
}

/*
 * 核心挂载函数 v3.3.2
 * 改用 PowerShell Mount-DiskImage，彻底解决：
 *   - 非标准扩展名（.lvm）问题：diskpart 对非 .vhd/.vhdx 扩展名静默失败
 *   - 中文路径问题：PowerShell 原生 Unicode，无编码问题
 *   - VDS 服务依赖：Mount-DiskImage 不依赖 Virtual Disk 服务
 *
 * 流程：
 *   1. 用 PowerShell Mount-DiskImage 挂载（支持任意扩展名）
 *   2. 等待新盘符出现（最多 30 秒）
 *   3. 用 PowerShell + manage-bde 解锁 BitLocker
 *
 * hWndParent: 用于弹出错误框，NULL 则静默
 * 返回 TRUE 表示成功
 */
static BOOL VaultMount(HWND hWndParent) {
    if (g_bVaultMounted) {
        if (hWndParent)
            MessageBoxW(hWndParent, L"保险箱已经挂载，无需重复操作。",
                        L"提示", MB_OK | MB_ICONINFORMATION);
        return TRUE;
    }

    if (!g_szVaultPath[0]) {
        if (hWndParent)
            MessageBoxW(hWndParent, L"请先设置伪装文件(.lvm)路径！",
                        L"错误", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    if (!g_szVaultPwd[0]) {
        if (hWndParent)
            MessageBoxW(hWndParent, L"请先设置 BitLocker 密码！",
                        L"错误", MB_OK | MB_ICONERROR);
        return FALSE;
    }

    WriteLog(L"VaultMount v3.3.3: 开始挂载 [%ls]", g_szVaultPath);

    /* ============================================================
     * v3.3.3 核心方案（参考 AppHider VHDXManager.cs）
     *
     * 根本原因：Mount-DiskImage 必须有 .vhdx/.iso 扩展名
     * 解决方案：创建临时符号链接 .lvm -> .vhdx，挂载符号链接
     * 挂载后用 Get-DiskImage 管道查询盘符（比等待盘符更可靠）
     * ============================================================ */

    /* 步骤1: 创建符号链接 BossVault_xxx.vhdx -> F:\system-bak.lvm */
    WriteLog(L"VaultMount: 步骤1 创建 .vhdx 符号链接");
    if (!CreateVaultSymlink()) {
        if (hWndParent) {
            WCHAR msg[512];
            _snwprintf(msg, 511,
                L"创建符号链接失败！\r\n\r\n"
                L"这通常是因为：\r\n"
                L"1. 未以管理员身份运行\r\n"
                L"2. Windows 未开启开发者模式（设置→更新和安全→开发者选项）\r\n\r\n"
                L"请先开启开发者模式或以管理员身份运行本程序。",
                0);
            msg[511] = 0;
            MessageBoxW(hWndParent, msg, L"符号链接失败", MB_OK | MB_ICONERROR);
        }
        return FALSE;
    }
    WriteLog(L"VaultMount: 符号链接已创建 [%ls]", g_szVaultSymlink);

    /* 步骤2: 记录挂载前盘符状态 */
    DWORD dwBefore = GetAllDrives();

    /* 步骤3: 用 PowerShell Mount-DiskImage 挂载符号链接（而非原始 .lvm） */
    WCHAR szPS[MAX_PATH + 256];
    _snwprintf(szPS, MAX_PATH + 255,
        L"Mount-DiskImage -ImagePath '%ls'",
        g_szVaultSymlink);
    szPS[MAX_PATH + 255] = 0;

    WriteLog(L"VaultMount: 步骤3 挂载符号链接: %ls", szPS);
    ExecPowerShell(szPS, TRUE, 30000);

    /* 步骤4: 用 Get-DiskImage 管道查询盘符（AppHider 方法） */
    WCHAR cDrive = 0;
    Sleep(2000);  /* 等待挂载稳定 */
    GetDriveLetterForImage(g_szVaultSymlink, &cDrive);

    /* 如果 PS 查询失败，退回等待盘符方法 */
    if (!cDrive) {
        WriteLog(L"VaultMount: Get-DiskImage 查询失败，尝试等待盘符出现");
        if (!WaitForDriveLetter(dwBefore, &cDrive, 20000)) {
            WriteLog(L"VaultMount: 等待盘符超时，挂载失败");
            CleanupVaultSymlink();
            if (hWndParent) {
                WCHAR msg[768];
                _snwprintf(msg, 767,
                    L"挂载失败！\r\n\r\n"
                    L"符号链接已创建，但 Mount-DiskImage 无法挂载。\r\n\r\n"
                    L"请在 PowerShell(管理员)手动测试：\r\n"
                    L"Mount-DiskImage -ImagePath '%ls'\r\n\r\n"
                    L"如果报错，请确认：\r\n"
                    L"1. 文件是否为有效的 VHDX 格式\r\n"
                    L"2. 以管理员身份运行本程序\r\n"
                    L"3. Win+R → services.msc → Virtual Disk → 启动",
                    g_szVaultPath);
                msg[767] = 0;
                MessageBoxW(hWndParent, msg, L"挂载失败！", MB_OK | MB_ICONERROR);
            }
            return FALSE;
        }
    }

    WriteLog(L"VaultMount: 盘符 %lc: 已确认", cDrive);

    /* 步骤5: 等待盘符稳定 */
    Sleep(1500);

    /* 步骤6: 用 PowerShell Unlock-BitLocker 解锁
     * 和 AppHider 相同的命令：
     *   $pw = ConvertTo-SecureString '密码' -AsPlainText -Force
     *   Unlock-BitLocker -MountPoint 'X:' -Password $pw
     */
    WCHAR szUnlockPS[1024];
    _snwprintf(szUnlockPS, 1023,
        L"$p = ConvertTo-SecureString '%ls' -AsPlainText -Force; "
        L"Unlock-BitLocker -MountPoint '%lc:' -Password $p",
        g_szVaultPwd, cDrive);
    szUnlockPS[1023] = 0;

    WriteLog(L"VaultMount: 步骤6 执行 BitLocker 解锁");
    ExecPowerShell(szUnlockPS, TRUE, 15000);

    /* 等待解锁完成 */
    Sleep(2000);

    /* 步骤7: 验证盘符是否可访问 */
    WCHAR szTest[8];
    _snwprintf(szTest, 7, L"%lc:\\", cDrive);
    DWORD attrs = GetFileAttributesW(szTest);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        WriteLog(L"VaultMount: 解锁后盘符 %lc: 无法访问，可能密码错误", cDrive);
        if (hWndParent) {
            WCHAR msg[256];
            _snwprintf(msg, 255,
                L"VHDX 已挂载为 %lc:，但 BitLocker 解锁失败。\r\n"
                L"请检查密码是否正确。",
                cDrive);
            msg[255] = 0;
            MessageBoxW(hWndParent, msg, L"BitLocker 解锁失败",
                        MB_OK | MB_ICONWARNING);
        }
        /* 即使解锁失败也记录盘符，以便后续弹出 */
        g_szVaultDrive[0] = cDrive;
        g_szVaultDrive[1] = L':';
        g_szVaultDrive[2] = 0;
        g_bVaultMounted = TRUE;
        return FALSE;
    }

    /* 挂载成功 */
    g_szVaultDrive[0] = cDrive;
    g_szVaultDrive[1] = L':';
    g_szVaultDrive[2] = 0;
    g_bVaultMounted = TRUE;

    WriteLog(L"VaultMount: 挂载成功，盘符=%ls", g_szVaultDrive);

    if (hWndParent) {
        WCHAR msg[128];
        _snwprintf(msg, 127, L"保险箱挂载成功！盘符: %ls", g_szVaultDrive);
        msg[127] = 0;
        MessageBoxW(hWndParent, msg, L"成功", MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}

/*
 * 核心弹出函数
 * 流程：
 *   1. manage-bde -lock 锁定 BitLocker
 *   2. 写 diskpart 脚本 detach vdisk
 *   3. 执行 diskpart
 *   4. 等待盘符消失
 *   5. 清理痕迹（文件管理器历史等）
 */
static BOOL VaultEject(HWND hWndParent) {
    if (!g_bVaultMounted) {
        if (hWndParent)
            MessageBoxW(hWndParent, L"保险箱未挂载。",
                        L"提示", MB_OK | MB_ICONINFORMATION);
        return TRUE;
    }

    WriteLog(L"VaultEject: 开始弹出 %ls", g_szVaultDrive);

    /* 步骤1: 先用 PowerShell 锁定 BitLocker（防止数据泄露） */
    if (g_szVaultDrive[0]) {
        WCHAR szLockPS[256];
        _snwprintf(szLockPS, 255,
            L"try { Lock-BitLocker -MountPoint '%lc:' -ForceDismount } "
            L"catch { manage-bde -lock %lc: -ForceDismount }",
            g_szVaultDrive[0], g_szVaultDrive[0]);
        szLockPS[255] = 0;
        ExecPowerShell(szLockPS, TRUE, 8000);
        Sleep(500);
    }

    /* 步骤2: 用 PowerShell Dismount-DiskImage 弹出
     * v3.3.3: 使用符号链接路径（和挂载时一致）
     */
    WCHAR szDismountPS[MAX_PATH + 256];
    /* 优先用符号链接路径，如果没有则用原始路径 */
    const WCHAR *pImagePath = (g_szVaultSymlink[0]) ? g_szVaultSymlink : g_szVaultPath;
    _snwprintf(szDismountPS, MAX_PATH + 255,
        L"Dismount-DiskImage -ImagePath '%ls'",
        pImagePath);
    szDismountPS[MAX_PATH + 255] = 0;

    WriteLog(L"VaultEject: 执行 PowerShell Dismount-DiskImage [%ls]", pImagePath);
    ExecPowerShell(szDismountPS, TRUE, 15000);

    /* 备用：如果 PowerShell 弹出失败，用 diskpart */
    Sleep(1000);
    DWORD dwAfter = GetAllDrives();
    if (g_szVaultDrive[0] && (dwAfter & (1u << (g_szVaultDrive[0] - 'A')))) {
        WriteLog(L"VaultEject: PowerShell 弹出后盘符仍存在，尝试 diskpart");
        EnsureVirtualDiskService();
        WCHAR szScript[MAX_PATH];
        GetTempPathW(MAX_PATH, szScript);
        wcsncat(szScript, L"vaulteject.txt", MAX_PATH - wcslen(szScript) - 1);
        HANDLE hFile = CreateFileW(szScript, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            BYTE bom[2] = {0xFF, 0xFE};
            DWORD written;
            WriteFile(hFile, bom, 2, &written, NULL);
            WCHAR szContent[1024];
            /* diskpart 备用也用符号链接路径 */
            _snwprintf(szContent, 1023,
                L"select vdisk file=\"%ls\"\r\n"
                L"detach vdisk\r\n",
                pImagePath);
            szContent[1023] = 0;
            WriteFile(hFile, szContent, (DWORD)(wcslen(szContent) * sizeof(WCHAR)),
                      &written, NULL);
            CloseHandle(hFile);
            WCHAR szCmd[MAX_PATH + 64];
            _snwprintf(szCmd, MAX_PATH + 63, L"diskpart /s \"%ls\"", szScript);
            szCmd[MAX_PATH + 63] = 0;
            DWORD exitCode = ExecHiddenEx(szCmd);
            WriteLog(L"VaultEject: diskpart 备用退出码=%lu", exitCode);
            DeleteFileW(szScript);
        }
    }

    /* 步骤3: 等待盘符消失 */
    Sleep(2000);

    /* 步骤3b: 删除符号链接（AppHider CleanupSymlink） */
    CleanupVaultSymlink();

    /* 步骤5: 清理文件管理器中的盘符访问记录 */
    /* 清理 Shell 文件夹历史（快速访问） */
    {
        WCHAR szPath[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath) == S_OK) {
            WCHAR szAuto[MAX_PATH];
            _snwprintf(szAuto, MAX_PATH-1,
                L"%ls\\Microsoft\\Windows\\Recent\\AutomaticDestinations", szPath);
            WCHAR szFind[MAX_PATH];
            _snwprintf(szFind, MAX_PATH-1, L"%ls\\*", szAuto);
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(szFind, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        WCHAR szFull[MAX_PATH];
                        _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls", szAuto, fd.cFileName);
                        SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                        DeleteFileW(szFull);
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    /* 清理最近文档 */
    {
        WCHAR szRecent[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, szRecent) == S_OK) {
            WCHAR szFind[MAX_PATH];
            _snwprintf(szFind, MAX_PATH-1, L"%ls\\*", szRecent);
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(szFind, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        WCHAR szFull[MAX_PATH];
                        _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls", szRecent, fd.cFileName);
                        SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                        DeleteFileW(szFull);
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    /* 清理注册表中的资源管理器路径历史 */
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
                0, KEY_WRITE|KEY_READ, &hKey) == ERROR_SUCCESS) {
            for (int i = 1; i <= 30; i++) {
                WCHAR v[8]; _snwprintf(v, 7, L"url%d", i);
                RegDeleteValueW(hKey, v);
            }
            RegCloseKey(hKey);
        }
    }

    /* 清理 RunMRU */
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");

    /* 通知 Shell 刷新 */
    SHChangeNotify(SHCNE_DRIVEREMOVED, SHCNF_PATH, g_szVaultDrive, NULL);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    g_bVaultMounted = FALSE;
    g_szVaultDrive[0] = 0;

    WriteLog(L"VaultEject: 弹出完成");

    if (hWndParent)
        MessageBoxW(hWndParent, L"保险箱已安全弹出，使用记录已清除。",
                    L"成功", MB_OK | MB_ICONINFORMATION);
    return TRUE;
}

/* 自动挂载（老板键进入时调用，静默） */
static void VaultAutoMount(void) {
    if (!g_szVaultPath[0] || !g_szVaultPwd[0]) return;
    VaultMount(NULL);
}

/* 自动弹出（老板键退出时调用，静默） */
static void VaultAutoEject(void) {
    if (!g_bVaultMounted) return;
    VaultEject(NULL);
}

/* ============================================================
   v3.5: 启动时恢复旧版遗留的VHDX挂载状态并强制卸载
   解决：更换版本后旧版挂载的VHDX无法卸载的问题
   ============================================================ */
static void VaultRecoverAndEject(void) {
    /* 如果当前已知挂载状态，直接卸载 */
    if (g_bVaultMounted) {
        VaultEject(NULL);
        return;
    }

    /* v4.1: 如果已知保险箱路径，直接尝试卸载（不管扫描是否成功）
     * 这样即使 Get-DiskImage 失败（PowerShell 执行策略问题），也能卸载 */
    if (g_szVaultPath[0]) {
        /* 先用 diskpart 直接尝试 detach */
        WCHAR szScript[MAX_PATH];
        GetTempPathW(MAX_PATH, szScript);
        wcsncat(szScript, L"vaultdirect.txt", MAX_PATH - wcslen(szScript) - 1);
        HANDLE hScr = CreateFileW(szScript, GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hScr != INVALID_HANDLE_VALUE) {
            BYTE bom[2] = {0xFF, 0xFE};
            DWORD wr;
            WriteFile(hScr, bom, 2, &wr, NULL);
            WCHAR szDp[MAX_PATH + 64];
            _snwprintf(szDp, MAX_PATH + 63,
                L"select vdisk file=\"%ls\"\r\ndetach vdisk\r\n", g_szVaultPath);
            WriteFile(hScr, szDp, (DWORD)(wcslen(szDp)*sizeof(WCHAR)), &wr, NULL);
            CloseHandle(hScr);
            WCHAR szCmd[MAX_PATH + 64];
            _snwprintf(szCmd, MAX_PATH + 63, L"diskpart /s \"%ls\"", szScript);
            ExecHiddenEx(szCmd);
            Sleep(2000);
            DeleteFileW(szScript);
        }
        /* 也尝试 PowerShell Dismount */
        WCHAR szDismount[MAX_PATH + 128];
        _snwprintf(szDismount, MAX_PATH + 127,
            L"Dismount-DiskImage -ImagePath '%ls' -ErrorAction SilentlyContinue",
            g_szVaultPath);
        szDismount[MAX_PATH + 127] = 0;
        ExecPowerShell(szDismount, TRUE, 10000);
    }

    /* 用 PowerShell 扫描所有已挂载的磁盘镜像（备用方案，处理未知路径的情况） */
    /* 把结果写到临时文件，再读取 */
    WCHAR szTmp[MAX_PATH];
    GetTempPathW(MAX_PATH, szTmp);
    wcsncat(szTmp, L"BossVaultScan.txt", MAX_PATH - wcslen(szTmp) - 1);
    DeleteFileW(szTmp);

    WCHAR szPS[MAX_PATH + 256];
    _snwprintf(szPS, MAX_PATH + 255,
        L"Get-DiskImage | Where-Object {$_.Attached -eq $true} | "
        L"Select-Object -ExpandProperty ImagePath | "
        L"Out-File -FilePath '%ls' -Encoding UTF8",
        szTmp);
    szPS[MAX_PATH + 255] = 0;
    ExecPowerShell(szPS, TRUE, 10000);

    /* 读取扫描结果 */
    HANDLE hFile = CreateFileW(szTmp, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > 65535) { CloseHandle(hFile); DeleteFileW(szTmp); return; }

    char *buf = (char*)HeapAlloc(GetProcessHeap(), 0, dwSize + 4);
    if (!buf) { CloseHandle(hFile); DeleteFileW(szTmp); return; }
    DWORD dwRead = 0;
    ReadFile(hFile, buf, dwSize, &dwRead, NULL);
    buf[dwRead] = 0;
    CloseHandle(hFile);
    DeleteFileW(szTmp);

    /* 转换为宽字符并逐行检查 */
    /* 跳过 UTF-8 BOM */
    char *p = buf;
    if (dwRead >= 3 && (BYTE)p[0]==0xEF && (BYTE)p[1]==0xBB && (BYTE)p[2]==0xBF) p += 3;

    /* 逐行处理 */
    while (*p) {
        /* 跳过空白 */
        while (*p == '\r' || *p == '\n' || *p == ' ') p++;
        if (!*p) break;

        /* 找到行尾 */
        char *lineStart = p;
        while (*p && *p != '\r' && *p != '\n') p++;
        int lineLen = (int)(p - lineStart);
        if (lineLen <= 0) continue;

        /* 转宽字符 */
        WCHAR szLine[MAX_PATH] = {0};
        MultiByteToWideChar(CP_UTF8, 0, lineStart, lineLen, szLine, MAX_PATH - 1);

        /* 检查是否包含 BossVault_ 或匹配 g_szVaultPath */
        BOOL bMatch = FALSE;
        if (wcsstr(szLine, L"BossVault_") != NULL) bMatch = TRUE;
        if (g_szVaultPath[0] && _wcsicmp(szLine, g_szVaultPath) == 0) bMatch = TRUE;
        /* 也检查不带扩展名的基本文件名 */
        if (!bMatch && g_szVaultPath[0]) {
            WCHAR *pBase = wcsrchr(g_szVaultPath, L'\\');
            if (pBase) {
                pBase++;
                if (wcsstr(szLine, pBase) != NULL) bMatch = TRUE;
            }
        }

        if (bMatch) {
            /* 找到遗留挂载，强制卸载 */
            WCHAR szDismount[MAX_PATH + 128];
            _snwprintf(szDismount, MAX_PATH + 127,
                L"Dismount-DiskImage -ImagePath '%ls'", szLine);
            szDismount[MAX_PATH + 127] = 0;
            ExecPowerShell(szDismount, TRUE, 15000);
            Sleep(1000);

            /* diskpart 备用 */
            WCHAR szScript[MAX_PATH];
            GetTempPathW(MAX_PATH, szScript);
            wcsncat(szScript, L"vaultrecover.txt", MAX_PATH - wcslen(szScript) - 1);
            HANDLE hScr = CreateFileW(szScript, GENERIC_WRITE, 0, NULL,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hScr != INVALID_HANDLE_VALUE) {
                BYTE bom[2] = {0xFF, 0xFE};
                DWORD wr;
                WriteFile(hScr, bom, 2, &wr, NULL);
                WCHAR szDp[MAX_PATH + 64];
                _snwprintf(szDp, MAX_PATH + 63,
                    L"select vdisk file=\"%ls\"\r\ndetach vdisk\r\n", szLine);
                WriteFile(hScr, szDp, (DWORD)(wcslen(szDp)*sizeof(WCHAR)), &wr, NULL);
                CloseHandle(hScr);
                WCHAR szCmd[MAX_PATH + 64];
                _snwprintf(szCmd, MAX_PATH + 63, L"diskpart /s \"%ls\"", szScript);
                ExecHiddenEx(szCmd);
                DeleteFileW(szScript);
            }

            /* 清理临时符号链接（BossVault_*.vhdx） */
            if (wcsstr(szLine, L"BossVault_") != NULL) {
                DeleteFileW(szLine);
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
}

/* ============================================================
   v3.3: 保险箱配置的保存/加载
   密码用简单 XOR 混淆存入注册表（不是加密，只是防止明文直接可见）
   ============================================================ */
#define VAULT_XOR_KEY 0x5A

static void SaveVaultConfig(void) {
    HKEY hKey;
    DWORD dwDisp;
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    for (int r = 0; r < 2; r++) {
        if (RegCreateKeyExW(roots[r], CONFIG_REG_KEY,
                            0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_WRITE, NULL, &hKey, &dwDisp) == ERROR_SUCCESS) {
            /* 保存路径（明文） */
            RegSetValueExW(hKey, L"VP", 0, REG_SZ,
                (LPBYTE)g_szVaultPath,
                (DWORD)((wcslen(g_szVaultPath)+1)*sizeof(WCHAR)));

            /* 保存密码（XOR 混淆） */
            int pwdLen = (int)wcslen(g_szVaultPwd);
            BYTE pwdBuf[256];
            for (int i = 0; i <= pwdLen; i++) {
                WCHAR c = g_szVaultPwd[i];
                pwdBuf[i*2]   = (BYTE)(c & 0xFF) ^ VAULT_XOR_KEY;
                pwdBuf[i*2+1] = (BYTE)((c >> 8) & 0xFF) ^ VAULT_XOR_KEY;
            }
            RegSetValueExW(hKey, L"VK", 0, REG_BINARY,
                pwdBuf, (DWORD)((pwdLen+1)*2));

            RegCloseKey(hKey);
            break;
        }
    }
}

static void LoadVaultConfig(void) {
    HKEY hKey;
    DWORD dwType, dwSize;
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    for (int r = 0; r < 2; r++) {
        if (RegOpenKeyExW(roots[r], CONFIG_REG_KEY,
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            /* 加载路径 */
            dwSize = sizeof(g_szVaultPath);
            RegQueryValueExW(hKey, L"VP", NULL, &dwType,
                             (LPBYTE)g_szVaultPath, &dwSize);

            /* 加载密码（XOR 解混淆） */
            BYTE pwdBuf[256] = {0};
            dwSize = sizeof(pwdBuf);
            if (RegQueryValueExW(hKey, L"VK", NULL, &dwType,
                                 pwdBuf, &dwSize) == ERROR_SUCCESS) {
                int chars = (int)(dwSize / 2);
                if (chars > 127) chars = 127;
                for (int i = 0; i < chars; i++) {
                    WCHAR c = (WCHAR)((pwdBuf[i*2] ^ VAULT_XOR_KEY) |
                              ((pwdBuf[i*2+1] ^ VAULT_XOR_KEY) << 8));
                    g_szVaultPwd[i] = c;
                }
                g_szVaultPwd[chars] = 0;
            }

            RegCloseKey(hKey);
            break;
        }
    }
}

/* ============================================================
   v3.2: 一键修复网络栈
   ============================================================ */
static void EmergencyNetworkFix(void) {
    /* ============================================================
       紧急网络修复 v4.0
       核心原则：绝不执行需要重启才能生效的命令！
       禁止：ipv4 reset / winsock reset / route flush /
             delete arpcache / delete destinationcache / delete address
       这些命令在不重启的情况下会让网络栈进入不一致状态，
       反而加重 ERR_NO_BUFFER_SPACE。

       正确策略（参考 AppHider EmergencyRestoreAsync）：
       1. 禁用再启用网卡（硬重置，清空所有连接状态）
       2. 重新设置IP（用 set 覆盖，不 delete）
       3. 确保DNS服务运行
       ============================================================ */

    /* v4.3: 步骤0: 使用 BeginNetworkChange 正确获取锁。
     * 之前用 InterlockedExchange 强制设置 g_lNetworkChangeBusy=1，
     * 会绕过自旋锁保护，导致和正在执行的 SetIPBoss/SetIPWork 冲突，
     * 造成两次 disable/enable 同时进行 → 双倍非分页池消耗。
     * 现在改为正确等待锁释放（最多120秒），紧急修复也遵守互斥。 */
    if (!BeginNetworkChange()) {
        WriteLog(L"EmergencyNetworkFix: 获取锁超时，放弃");
        return;
    }

    const WCHAR *adpName = GetAdapterName();
    WCHAR args[1024];

    /* ----------------------------------------------------------
       步骤1: 禁用网卡（硬重置所有TCP/UDP连接和缓冲区）
       这是解决 ERR_NO_BUFFER_SPACE 最有效的方法：
       禁用网卡会让 Windows 立即释放该网卡上所有的
       socket缓冲区、连接状态、非分页池内存。
       ---------------------------------------------------------- */
    _snwprintf(args, 1023,
        L"interface set interface name=\"%ls\" admin=disabled",
        adpName);
    RunNetshDirect(args);
    Sleep(2000);

    /* ----------------------------------------------------------
       步骤2: 启用网卡（网卡重新初始化，缓冲区全部清空）
       ---------------------------------------------------------- */
    _snwprintf(args, 1023,
        L"interface set interface name=\"%ls\" admin=enabled",
        adpName);
    RunNetshDirect(args);
    Sleep(3000);  /* 等待网卡完全就绪 */

    /* v4.3: 使适配器名称缓存失效（同 RandomizeMac 中的处理） */
    g_szAdapter[0] = 0;
    /* v4.3: 记录操作时间戳，防止 IPGuardThread 级联恢复 */
    InterlockedExchange(&g_dwLastNetworkResetTick, (LONG)GetTickCount());

    /* ----------------------------------------------------------
       步骤2.5: v4.2 清理网卡上所有残留IP
       禁用/启用网卡后，Windows 可能保留之前的静态IP配置。
       如果不清理，反复紧急修复也会导致IP累积。
       ---------------------------------------------------------- */
    ClearAccumulatedIPs();

    /* ----------------------------------------------------------
       步骤3: 确保 DNS Client 服务运行
       ---------------------------------------------------------- */
    ExecHidden(L"net start Dnscache");

    /* ----------------------------------------------------------
       步骤4: 重新应用正确的 IP（用 set 覆盖，不 delete）
       ---------------------------------------------------------- */
    if (g_bBossMode) {
        wcsncpy(g_szExpectedIP, IP_BOSS, 63);
        _snwprintf(args, 1023,
            L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls store=active",
            adpName, IP_BOSS, IP_BOSS_MASK, IP_BOSS_GW);
        RunNetshDirect(args);
        Sleep(500);
        _snwprintf(args, 1023,
            L"interface ipv4 set dnsservers name=\"%ls\" source=static address=%ls register=none validate=no store=active",
            adpName, IP_BOSS_DNS);
        RunNetshDirect(args);
    } else {
        wcsncpy(g_szExpectedIP, IP_WORK1, 63);
        _snwprintf(args, 1023,
            L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls store=active",
            adpName, IP_WORK1, IP_WORK_MASK, IP_WORK_GW);
        RunNetshDirect(args);
        Sleep(500);
        _snwprintf(args, 1023,
            L"interface ipv4 add address name=\"%ls\" addr=%ls mask=%ls store=active",
            adpName, IP_WORK2, IP_WORK_MASK);
        RunNetshDirect(args);
        Sleep(300);
        _snwprintf(args, 1023,
            L"interface ipv4 set dnsservers name=\"%ls\" source=static address=%ls register=none validate=no store=active",
            adpName, IP_WORK_DNS);
        RunNetshDirect(args);
    }

    ExecHidden(L"ipconfig /flushdns");
    Sleep(500);

    /* 步骤5: 恢复 IPGuard */
    EndNetworkChange();
}

DWORD WINAPI EmergencyFixThread(LPVOID p) {
    (void)p;
    if (InterlockedCompareExchange(&g_lEmergencyFixBusy, 1, 0) != 0) return 0;
    MessageBeep(MB_ICONEXCLAMATION);
    EmergencyNetworkFix();
    InterlockedExchange(&g_lEmergencyFixBusy, 0);
    MessageBeep(MB_OK);
    return 0;
}

/* ============================================================
   进程保护
   ============================================================ */
static void ProtectProcess(void) {
    /* 第一步：开启 SeDebugPrivilege（调试权限），让自己能操作其他进程 */
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }

    /* v4.12: 第二步：修改自身进程的 DACL
     * 策略：只拒绝 "Users" 组（普通用户）的 PROCESS_TERMINATE
     *         管理员组不受限制，依然可以用专用工具结束进程
     * v4.11 的错误：拒绝 Everyone 把管理员自己也锁死了
     *
     * v4.19.2 修复 v4.12 的隐藏 bug：
     *   Windows 管理员默认也属于 Users 组（Microsoft 设计），所以 v4.12 单纯
     *   拒绝 Users 也会拒绝管理员自己，导致 BossToolKiller/BossToolForceExit
     *   杀不掉（OpenProcess 被 DACL 拒绝拿不到句柄，SeDebugPrivilege 也不能
     *   bypass DENY ACE）。
     *   修复：DACL 顺序改为 [ALLOW Administrators, DENY Users, 原 ACE...]，
     *   ALLOW Administrators ACE 在 DENY Users 之前，DACL 查找时第一个匹配
     *   的 ACE 生效 → 管理员永远匹配 ALLOW 通过；普通用户匹配 DENY 拒绝。 */
    {
        HANDLE hProc = GetCurrentProcess();
        PSECURITY_DESCRIPTOR pSD = NULL;
        PACL pOldDacl = NULL;
        if (GetSecurityInfo(hProc, SE_KERNEL_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            NULL, NULL, &pOldDacl, NULL, &pSD) == ERROR_SUCCESS) {
            EXPLICIT_ACCESS_W ea[2];
            ZeroMemory(ea, sizeof(ea));
            /* ACE 1: 先 ALLOW Administrators（管理员永远通过） */
            ea[0].grfAccessPermissions = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                         PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE |
                                         READ_CONTROL | PROCESS_QUERY_INFORMATION;
            ea[0].grfAccessMode        = GRANT_ACCESS;
            ea[0].grfInheritance       = NO_INHERITANCE;
            ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_NAME;
            ea[0].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[0].Trustee.ptstrName    = (LPWSTR)L"Administrators";
            /* ACE 2: 再 DENY Users（普通用户被拒绝，不影响管理员因为已 ALLOW） */
            ea[1].grfAccessPermissions = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            ea[1].grfAccessMode        = DENY_ACCESS;
            ea[1].grfInheritance       = NO_INHERITANCE;
            ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_NAME;
            ea[1].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[1].Trustee.ptstrName    = (LPWSTR)L"Users";
            PACL pNewDacl = NULL;
            if (SetEntriesInAclW(2, ea, pOldDacl, &pNewDacl) == ERROR_SUCCESS) {
                SetSecurityInfo(hProc, SE_KERNEL_OBJECT,
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, pNewDacl, NULL);
                LocalFree(pNewDacl);
            }
            LocalFree(pSD);
        }
    }
}

/* ============================================================
   看门狗线程
   ============================================================ */
/* v4.13: 锁屏功能已删除， KillBypassWindows 和 WatchdogThread 一并移除 */

/* v4.13: 锁屏功能已删除， GuardThread 一并移除 */

/* ============================================================
   配置读写
   ============================================================ */
static void SaveConfig(void);   /* 前向声明：LoadConfig 迁移时需要调用 */
static void LoadConfig(void) {
    HKEY hKey;
    DWORD dwType, dwSize;
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    for (int r = 0; r < 2; r++) {
        if (RegOpenKeyExW(roots[r], CONFIG_REG_KEY,
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            dwSize = sizeof(g_szLoginPwd);
            RegQueryValueExW(hKey, L"LP", NULL, &dwType,
                             (LPBYTE)g_szLoginPwd, &dwSize);
            dwSize = sizeof(g_szLockPwd);
            RegQueryValueExW(hKey, L"SP", NULL, &dwType,
                             (LPBYTE)g_szLockPwd, &dwSize);
            dwSize = sizeof(g_BossMod);
            RegQueryValueExW(hKey, L"BM", NULL, &dwType,
                             (LPBYTE)&g_BossMod, &dwSize);
            dwSize = sizeof(g_BossVk);
            RegQueryValueExW(hKey, L"BK", NULL, &dwType,
                             (LPBYTE)&g_BossVk, &dwSize);
            dwSize = sizeof(g_bAutoRun);
            RegQueryValueExW(hKey, L"AR", NULL, &dwType,
                             (LPBYTE)&g_bAutoRun, &dwSize);
            dwSize = sizeof(g_szHideList);
            RegQueryValueExW(hKey, L"HL", NULL, &dwType,
                             (LPBYTE)g_szHideList, &dwSize);
            /* v4.7: 配置版本迁移 — 旧版注册表无 CV 或版本不匹配时，
             * 重置老板键为新默认值 Ctrl+Win+Alt（纯修饰键，由钩子处理） */
            DWORD dwVer = 0;
            dwSize = sizeof(dwVer);
            if (RegQueryValueExW(hKey, L"CV", NULL, &dwType,
                                 (LPBYTE)&dwVer, &dwSize) != ERROR_SUCCESS
                || dwVer < CONFIG_VERSION) {
                g_BossMod = DEFAULT_BOSS_MOD;
                g_BossVk  = DEFAULT_BOSS_VK;
                RegCloseKey(hKey);
                SaveConfig();   /* 写入新默认值 + 版本号 */
                WriteLog(L"Config migrated to v%d: boss hotkey -> Ctrl+Win+Alt (hook)",
                         CONFIG_VERSION);
                /* 加载保险箱配置 */
                LoadVaultConfig();
                return;
            }
            RegCloseKey(hKey);
            break;
        }
    }
    /* 保存当前配置版本号（首次安装或已是最新版） */
    {
        DWORD dwVer = 0; dwSize = sizeof(dwVer);
        BOOL bNeedSave = FALSE;
        for (int r = 0; r < 2; r++) {
            if (RegOpenKeyExW(roots[r], CONFIG_REG_KEY,
                              0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                dwSize = sizeof(dwVer);
                if (RegQueryValueExW(hKey, L"CV", NULL, &dwType,
                                     (LPBYTE)&dwVer, &dwSize) != ERROR_SUCCESS
                    || dwVer < CONFIG_VERSION) {
                    bNeedSave = TRUE;
                }
                RegCloseKey(hKey);
                break;
            }
        }
        if (bNeedSave) SaveConfig();
    }
    /* 加载保险箱配置 */
    LoadVaultConfig();
}

static void SaveConfig(void) {
    HKEY hKey;
    DWORD dwDisp;
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    for (int r = 0; r < 2; r++) {
        if (RegCreateKeyExW(roots[r], CONFIG_REG_KEY,
                            0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_WRITE, NULL, &hKey, &dwDisp) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"LP", 0, REG_SZ,
                (LPBYTE)g_szLoginPwd,
                (DWORD)((wcslen(g_szLoginPwd)+1)*sizeof(WCHAR)));
            RegSetValueExW(hKey, L"SP", 0, REG_SZ,
                (LPBYTE)g_szLockPwd,
                (DWORD)((wcslen(g_szLockPwd)+1)*sizeof(WCHAR)));
            RegSetValueExW(hKey, L"BM", 0, REG_DWORD,
                (LPBYTE)&g_BossMod, sizeof(DWORD));
            RegSetValueExW(hKey, L"BK", 0, REG_DWORD,
                (LPBYTE)&g_BossVk, sizeof(DWORD));
            RegSetValueExW(hKey, L"AR", 0, REG_DWORD,
                (LPBYTE)&g_bAutoRun, sizeof(DWORD));
            RegSetValueExW(hKey, L"HL", 0, REG_SZ,
                (LPBYTE)g_szHideList,
                (DWORD)((wcslen(g_szHideList)+1)*sizeof(WCHAR)));
            /* v4.5: 写入配置版本号，用于升级时自动迁移 */
            {
                DWORD dwVer = CONFIG_VERSION;
                RegSetValueExW(hKey, L"CV", 0, REG_DWORD,
                    (LPBYTE)&dwVer, sizeof(DWORD));
            }
            RegCloseKey(hKey);
            break;
        }
    }
    /* 保存保险箱配置 */
    SaveVaultConfig();
}

static void SetAutoRun(BOOL bEnable) {
    HKEY hKey;
    HKEY roots[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    for (int r = 0; r < 2; r++) {
        if (RegOpenKeyExW(roots[r], AUTORUN_REG_KEY,
                          0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            if (bEnable) {
                WCHAR szPath[MAX_PATH+32];
                WCHAR szExe[MAX_PATH];
                GetModuleFileNameW(NULL, szExe, MAX_PATH);
                _snwprintf(szPath, MAX_PATH+31, L"\"%ls\" /autostart", szExe);
                RegSetValueExW(hKey, AUTORUN_VALUE_NAME, 0, REG_SZ,
                    (LPBYTE)szPath,
                    (DWORD)((wcslen(szPath)+1)*sizeof(WCHAR)));
            } else {
                RegDeleteValueW(hKey, AUTORUN_VALUE_NAME);
            }
            RegCloseKey(hKey);
            break;
        }
    }
}

/* ============================================================
   获取网络适配器名称
   ============================================================ */
static const WCHAR* GetAdapterName(void) {
    if (g_szAdapter[0]) return g_szAdapter;
    ULONG bufLen = 32768;
    PIP_ADAPTER_ADDRESSES pAddrs = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
    if (!pAddrs) { wcscpy(g_szAdapter, L"以太网"); return g_szAdapter; }
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX,
                              NULL, pAddrs, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES p = pAddrs;
        while (p) {
            if ((p->IfType == IF_TYPE_ETHERNET_CSMACD ||
                 p->IfType == IF_TYPE_IEEE80211) &&
                p->OperStatus == IfOperStatusUp) {
                wcsncpy(g_szAdapter, p->FriendlyName, 255);
                free(pAddrs);
                return g_szAdapter;
            }
            p = p->Next;
        }
        p = pAddrs;
        while (p) {
            if (p->IfType == IF_TYPE_ETHERNET_CSMACD ||
                p->IfType == IF_TYPE_IEEE80211) {
                wcsncpy(g_szAdapter, p->FriendlyName, 255);
                free(pAddrs);
                return g_szAdapter;
            }
            p = p->Next;
        }
    }
    free(pAddrs);
    wcscpy(g_szAdapter, L"以太网");
    return g_szAdapter;
}

/* ============================================================
   IP 管理
   ============================================================ */
static DWORD GetEthernetIfIndex(void) {
    ULONG bufLen = 16384;
    PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)malloc(bufLen);
    if (!pInfo) return 0;
    DWORD idx = 0;
    if (GetAdaptersInfo(pInfo, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO p = pInfo;
        while (p) {
            if (p->Type == MIB_IF_TYPE_ETHERNET ||
                p->Type == IF_TYPE_IEEE80211) {
                idx = p->Index;
                break;
            }
            p = p->Next;
        }
    }
    free(pInfo);
    return idx;
}

static void RandomizeMac(void) {
    /* v4.3: 冷却检查 — 防止短时间内反复禁用/启用网卡
     * 每次 disable/enable 会让 Windows TCP/IP 栈完全重建，
     * 消耗大量非分页池内存（NDIS buffer pools、ARP tables 等）。
     * 如果冷却期未到，直接跳过，避免资源耗尽。 */
    DWORD dwNow = GetTickCount();
    DWORD dwLast = (DWORD)g_dwLastMacRandomizeTick;
    if (dwLast != 0 && (dwNow - dwLast) < (DWORD)MAC_COOLDOWN_MS) {
        WriteLog(L"RandomizeMac: 冷却中（距上次 %lu 秒），跳过",
                 (dwNow - dwLast) / 1000);
        return;
    }

    srand((unsigned)(GetTickCount() ^ (DWORD)(ULONG_PTR)&RandomizeMac ^ GetCurrentProcessId()));
    BYTE mac[6];
    mac[0] = 0x02;
    mac[1] = (BYTE)(rand() % 256);
    mac[2] = (BYTE)(rand() % 256);
    mac[3] = (BYTE)(rand() % 256);
    mac[4] = (BYTE)(rand() % 256);
    do { mac[5] = (BYTE)(rand() % 256); } while (mac[5] == 0);
    WCHAR szMac[16];
    _snwprintf(szMac, 15, L"%02X%02X%02X%02X%02X%02X",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    WriteLog(L"RandomizeMac: target MAC=%ls", szMac);

    const WCHAR *szClass =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4D36E972-E325-11CE-BFC1-08002BE10318}";
    HKEY hClass;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szClass, 0,
                      KEY_READ, &hClass) != ERROR_SUCCESS) return;

    BOOL bSet = FALSE;
    for (DWORD i = 0; i < 128; i++) {
        WCHAR szIdx[8];
        _snwprintf(szIdx, 7, L"%04lu", i);
        HKEY hSub;
        if (RegOpenKeyExW(hClass, szIdx, 0,
                          KEY_READ | KEY_WRITE, &hSub) != ERROR_SUCCESS)
            continue;
        WCHAR szDesc[256] = {0};
        DWORD cbDesc = sizeof(szDesc);
        RegQueryValueExW(hSub, L"DriverDesc", NULL, NULL,
                         (LPBYTE)szDesc, &cbDesc);
        DWORD dwIfType = 0;
        DWORD cbIft = sizeof(DWORD);
        DWORD dwIftType = 0;
        RegQueryValueExW(hSub, L"*IfType", NULL, &dwIftType,
                         (LPBYTE)&dwIfType, &cbIft);

        BOOL bIsPhysical = (dwIfType == 6 || dwIfType == 71);
        if (!bIsPhysical && szDesc[0]) {
            const WCHAR *kws[] = {
                L"Realtek", L"Intel", L"Broadcom", L"Qualcomm",
                L"Atheros", L"Marvell", L"Killer", L"Ethernet",
                L"Network Adapter", L"LAN", L"NIC", NULL
            };
            for (int k = 0; kws[k]; k++)
                if (wcsstr(szDesc, kws[k])) { bIsPhysical = TRUE; break; }
        }
        if (bIsPhysical && szDesc[0]) {
            const WCHAR *excl[] = {
                L"Virtual", L"Hyper-V", L"VPN", L"TAP", L"Loopback",
                L"Miniport", L"WAN", L"PPP", L"Bluetooth",
                L"Microsoft", L"Kernel Debug", L"NDIS", L"Filter",
                L"Tunnel", L"Teredo", L"6to4", L"ISATAP", NULL
            };
            for (int k = 0; excl[k]; k++)
                if (wcsstr(szDesc, excl[k])) { bIsPhysical = FALSE; break; }
        }
        if (bIsPhysical) {
            DWORD cbMac = (DWORD)((wcslen(szMac) + 1) * sizeof(WCHAR));
            LONG lRet = RegSetValueExW(hSub, L"NetworkAddress", 0, REG_SZ,
                                       (LPBYTE)szMac, cbMac);
            if (lRet == ERROR_SUCCESS) { bSet = TRUE; RegCloseKey(hSub); break; }
        }
        RegCloseKey(hSub);
    }
    RegCloseKey(hClass);

    if (!bSet) return;

    /* v4.0: 用 netsh 禁用/启用网卡（不经过 cmd.exe，避免引号被吃掉）
     * 之前用 wmic 通过 ExecHidden(cmd.exe /c wmic ... "Name='xxx'") 时，
     * cmd.exe 会把内层引号吃掉，导致 wmic 收到残缺命令。
     * 改用 RunNetshDirect 直接调用 netsh.exe（CreateProcess，不经过 cmd.exe）
     */
    const WCHAR *adpName = GetAdapterName();
    WCHAR args[512];
    _snwprintf(args, 511,
        L"interface set interface name=\"%ls\" admin=disabled",
        adpName);
    RunNetshDirect(args);
    Sleep(800);  /* v4.4: 1500→800ms，足够等待网卡禁用 */
    _snwprintf(args, 511,
        L"interface set interface name=\"%ls\" admin=enabled",
        adpName);
    RunNetshDirect(args);
    Sleep(1000);  /* v4.4: 2000→1000ms，足够等待网卡启用 */

    /* v4.3: 记录操作时间戳（供 IPGuardThread 冷却判断） */
    InterlockedExchange(&g_dwLastMacRandomizeTick, (LONG)GetTickCount());
    InterlockedExchange(&g_dwLastNetworkResetTick, (LONG)GetTickCount());

    /* v4.3: 使适配器名称缓存失效。
     * 禁用/启用网卡后，Windows 可能重新命名适配器（如 "以太网 2"），
     * 旧缓存名称会导致后续 netsh 命令静默失败。 */
    g_szAdapter[0] = 0;
}

/* netsh 直接调用 */
static DWORD RunNetshDirect(const WCHAR *args) {
    WCHAR szNetsh[MAX_PATH] = {0};
    GetSystemDirectoryW(szNetsh, MAX_PATH);
    wcsncat(szNetsh, L"\\netsh.exe", MAX_PATH - wcslen(szNetsh) - 1);

    WCHAR cmdLine[1024];
    _snwprintf(cmdLine, 1023, L"\"%ls\" %ls", szNetsh, args);
    cmdLine[1023] = 0;

    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    DWORD exitCode = 1;
    if (CreateProcessW(szNetsh, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return exitCode;
}

/* ============================================================
   v4.2 修复：清除适配器上累积的残留IP地址
   根因：每次 RandomizeMac 禁用/启用网卡后，Windows 网络栈
   可能保留之前的静态IP配置。反复切换导致多个残留IP堆积，
   最终耗尽非分页池缓冲区 → ERR_NO_BUFFER_SPACE (10055)。
   ============================================================ */
static void ClearAccumulatedIPs(void) {
    const WCHAR *adpName = GetAdapterName();
    if (!adpName || !adpName[0]) return;

    WriteLog(L"ClearAccumulatedIPs: 清理适配器 [%ls] 上的残留IP", adpName);

    /* 反复尝试 delete address 直到没有更多静态IP可删。
     * netsh delete address 只删除非主静态IP，不会触发大规模socket释放。
     * 最多循环20次防止意外死循环。 */
    WCHAR args[512];
    BOOL deleted;
    int pass = 0;
    do {
        deleted = FALSE;
        /* 尝试通过 PowerShell 获取适配器上所有静态IP并逐个删除 */
        WCHAR psScript[1024];
        WCHAR psOutput[4096] = {0};
        _snwprintf(psScript, 1023,
            L"(Get-NetIPAddress -InterfaceAlias '%ls' -AddressFamily IPv4).IPAddress",
            adpName);
        if (ExecPowerShellWithOutput(psScript, psOutput, 4095)) {
            /* 解析输出，每行一个IP */
            WCHAR *line = psOutput;
            while (*line) {
                WCHAR *eol = wcschr(line, L'\n');
                if (eol) { *eol = 0; if (eol > line && *(eol-1) == L'\r') *(eol-1) = 0; }
                /* 去除前后空白 */
                while (*line == L' ' || *line == L'\t') line++;
                WCHAR *end = line + wcslen(line) - 1;
                while (end > line && (*end == L' ' || *end == L'\t' || *end == L'\r')) *end-- = 0;

                if (line[0] &&
                    wcscmp(line, L"127.0.0.1") != 0 &&
                    wcscmp(line, L"0.0.0.0") != 0) {
                    /* 删除这个IP（忽略错误，可能有些IP是DHDP不可删） */
                    _snwprintf(args, 511,
                        L"interface ipv4 delete address name=\"%ls\" addr=%ls store=active",
                        adpName, line);
                    DWORD ret = RunNetshDirect(args);
                    if (ret == 0) {
                        deleted = TRUE;
                        WriteLog(L"ClearAccumulatedIPs: 已删除残留IP %ls", line);
                    }
                }
                line = eol ? eol + 1 : line + wcslen(line);
            }
        }
        pass++;
    } while (deleted && pass < 20);

    WriteLog(L"ClearAccumulatedIPs: 清理完成，共 %d 轮", pass);
    Sleep(200);  /* v4.4: 500→200ms，足够等待网络栈稳定 */
}

static void ApplyIP(const WCHAR *ip1, const WCHAR *mask1, const WCHAR *gw,
                    const WCHAR *dns, const WCHAR *ip2, const WCHAR *mask2) {
    const WCHAR *adpName = GetAdapterName();
    DWORD ifIdx = GetEthernetIfIndex();
    WCHAR args[512];
    BOOL bOK = FALSE;
    DWORD ret;

    /* v4.4: 移除重复的 ClearAccumulatedIPs() 调用。
     * SetIPBoss/SetIPWork 已在 RandomizeMac 之后调用过 ClearAccumulatedIPs，
     * 这里再调一次是浪费（每次 ~2-3秒）。
     * IPGuardThread 调用 ApplyIP 前也先调了 ClearAccumulatedIPs。
     * 所以这里不需要重复清理。 */

    WriteLog(L"ApplyIP: [adapter=%ls] ip=%ls", adpName, ip1);

    /* 方案A: ipv4 set address 直接覆盖（不delete） */
    _snwprintf(args, 511,
        L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls store=active",
        adpName, ip1, mask1, gw);
    ret = RunNetshDirect(args);
    Sleep(100);  /* v4.4: 300→100ms */
    WriteLog(L"ApplyIP A ret=%lu", ret);
    if (ret == 0) bOK = TRUE;

    if (!bOK) {
        /* 方案B: 不带 store=active */
        _snwprintf(args, 511,
            L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls",
            adpName, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(100);  /* v4.4: 300→100ms */
        WriteLog(L"ApplyIP B ret=%lu", ret);
        if (ret == 0) bOK = TRUE;
    }

    if (!bOK && ifIdx > 0) {
        /* 方案C: 用接口索引 */
        _snwprintf(args, 511,
            L"interface ip set address %lu static %ls %ls %ls 1",
            ifIdx, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(100);  /* v4.4: 300→100ms */
        WriteLog(L"ApplyIP C ret=%lu", ret);
    }

    /* v4.2 修复：第二IP先 delete 再 add，防止累积！
     * 之前只 add 不 delete，每次切换都追加一个 192.168.1.88，
     * 几天后累积几十个相同IP → 耗尽网络栈缓冲区 → ERR_NO_BUFFER_SPACE。
     * delete 失败（不存在）是无害的，继续 add 即可。 */
    if (ip2 && ip2[0]) {
        /* 先删除（忽略错误） */
        _snwprintf(args, 511,
            L"interface ipv4 delete address name=\"%ls\" addr=%ls store=active",
            adpName, ip2);
        RunNetshDirect(args);
        Sleep(100);
        /* 再添加 */
        _snwprintf(args, 511,
            L"interface ipv4 add address name=\"%ls\" addr=%ls mask=%ls store=active",
            adpName, ip2, mask2);
        RunNetshDirect(args);
        Sleep(200);
    }

    if (dns && dns[0]) {
        _snwprintf(args, 511,
            L"interface ipv4 set dnsservers name=\"%ls\" source=static address=%ls register=none validate=no store=active",
            adpName, dns);
        RunNetshDirect(args);
    }

    ExecHidden(L"ipconfig /flushdns");
    WriteLog(L"ApplyIP done");
}

static void LockIPReg(void) {
    HKEY hKey; DWORD dwDisp; DWORD v = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE,
            NULL, &hKey, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"NC_AllowAdvancedTCPIPConfig",
                       0, REG_DWORD, (LPBYTE)&v, sizeof(v));
        RegCloseKey(hKey);
    }
}

static void UnlockIPReg(void) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"NC_AllowAdvancedTCPIPConfig");
        RegCloseKey(hKey);
    }
}

static BOOL AdapterHasIP(const WCHAR *expectedIP) {
    ULONG bufLen = 16384;
    PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)malloc(bufLen);
    if (!pInfo) return FALSE;
    BOOL found = FALSE;
    char expectedA[64] = {0};
    WideCharToMultiByte(CP_ACP, 0, expectedIP, -1, expectedA, 63, NULL, NULL);
    if (GetAdaptersInfo(pInfo, &bufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO p = pInfo;
        while (p && !found) {
            if (p->Type == MIB_IF_TYPE_ETHERNET || p->Type == IF_TYPE_IEEE80211) {
                IP_ADDR_STRING *addr = &p->IpAddressList;
                while (addr) {
                    if (addr->IpAddress.String[0] &&
                        strcmp(addr->IpAddress.String, "0.0.0.0") != 0 &&
                        strcmp(addr->IpAddress.String, expectedA) == 0) {
                        found = TRUE; break;
                    }
                    addr = addr->Next;
                }
            }
            p = p->Next;
        }
    }
    free(pInfo);
    return found;
}

DWORD WINAPI IPGuardThread(LPVOID p) {
    (void)p;
    Sleep(10000);  /* v4.2: 启动等待更长，避免和 InitialIPThread 冲突 */
    /* v4.19: 注册表策略项周期性再清理 — 每 24 小时一次
     * 见 CleanupLockWorkstationPolicy() 注释了解根因。 */
    DWORD dwLastPolicyCleanupTick = 0;
    const DWORD POLICY_CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000;  /* 24h */
    while (1) {
        Sleep(15000);  /* v4.2: 5秒→15秒，减少 GetAdaptersInfo 调用和网络栈压力 */

        /* v4.19: 周期性清理锁屏策略项（运行中被域控/第三方重新设置时兜底） */
        {
            DWORD dwNow = GetTickCount();
            if (dwLastPolicyCleanupTick == 0) {
                dwLastPolicyCleanupTick = dwNow;
            } else if ((dwNow - dwLastPolicyCleanupTick) >= POLICY_CLEANUP_INTERVAL_MS) {
                dwLastPolicyCleanupTick = dwNow;
                CleanupLockWorkstationPolicy();
            }
        }

        if (g_bAllowIPChange || g_szExpectedIP[0] == 0) continue;
        if (g_lNetworkChangeBusy) continue;

        /* v4.3: 冷却检查 — RandomizeMac 后60秒内不触发IP恢复。
         * 网卡刚禁用/启用后，TCP/IP 栈还在重建中，此时检查IP
         * 会发现"IP丢失"→ 触发大量 netsh/PowerShell 进程 → 级联崩溃。
         * 等待60秒让网络栈完全稳定后再检查。 */
        {
            DWORD dwNow = GetTickCount();
            DWORD dwReset = (DWORD)g_dwLastNetworkResetTick;
            if (dwReset != 0 && (dwNow - dwReset) < (DWORD)IPGUARD_COOLDOWN_MS) {
                continue;  /* 冷却中，跳过本次检查 */
            }
        }

        if (!AdapterHasIP(g_szExpectedIP)) {
            Sleep(30000);  /* v4.2: 15秒→30秒，给适配器更多恢复时间 */
            if (g_bAllowIPChange || g_szExpectedIP[0] == 0) continue;
            if (g_lNetworkChangeBusy || AdapterHasIP(g_szExpectedIP)) continue;

            /* v4.3: 再次检查冷却（30秒等待期间可能已满足冷却条件） */
            {
                DWORD dwNow = GetTickCount();
                DWORD dwReset = (DWORD)g_dwLastNetworkResetTick;
                if (dwReset != 0 && (dwNow - dwReset) < (DWORD)IPGUARD_COOLDOWN_MS) {
                    continue;
                }
            }

            /* v3.3.4: 用 BeginNetworkChange 保护，防止和 EmergencyFix 冲突 */
            if (!BeginNetworkChange()) continue;
            WriteLog(L"IPGuardThread: IP 丢失，清理残留后重新应用");
            /* v4.2: 先清理残留IP再重新应用，防止累积 */
            ClearAccumulatedIPs();
            if (g_bBossMode)
                ApplyIP(IP_BOSS, IP_BOSS_MASK, IP_BOSS_GW, NULL, NULL, NULL);
            else
                ApplyIP(IP_WORK1, IP_WORK_MASK, IP_WORK_GW,
                        IP_WORK_DNS, IP_WORK2, IP_WORK_MASK);
            EndNetworkChange();
        }
    }
    return 0;
}

/* ============================================================
   记事本控制
   ============================================================ */
static void OpenNotepad(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"notepad.exe") == 0) {
                    CloseHandle(hSnap);
                    return;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    WCHAR szNotepad[MAX_PATH];
    GetSystemDirectoryW(szNotepad, MAX_PATH);
    wcsncat(szNotepad, L"\\notepad.exe", MAX_PATH - wcslen(szNotepad) - 1);
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    if (CreateProcessW(szNotepad, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static void CloseNotepad(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"notepad.exe") == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) { TerminateProcess(hProc, 0); CloseHandle(hProc); }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

/* v4.4: RandomizeMac 的线程包装函数 */
static DWORD WINAPI RandomizeMacThread(LPVOID p) {
    (void)p;
    RandomizeMac();
    return 0;
}

static void SetIPWork(void) {
    /* v4.4: MAC随机化移至后台线程，不阻塞IP切换。
     * RandomizeMac 需要 disable/enable 网卡 (~5s)，
     * 如果在主线程执行会让老板键切换等待太久。
     * 放到后台线程后，IP切换只需 ~2-3秒。
     * RandomizeMac 内部有 BeginNetworkChange 锁，
     * 不会和下面的 ApplyIP 冲突。 */
    if (g_bEnableMacRandomization)
        StartDetachedThread(RandomizeMacThread, NULL);
    if (!BeginNetworkChange()) return;
    /* v4.2: 清理残留IP（RandomizeMac 在后台运行，这里先清理旧IP） */
    ClearAccumulatedIPs();
    wcsncpy(g_szExpectedIP, IP_WORK1, 63);
    ApplyIP(IP_WORK1, IP_WORK_MASK, IP_WORK_GW, IP_WORK_DNS, IP_WORK2, IP_WORK_MASK);
    LockIPReg();
    CloseNotepad();
    EndNetworkChange();
}

static void SetIPBoss(void) {
    /* v4.4: 同上，MAC随机化移至后台 */
    if (g_bEnableMacRandomization)
        StartDetachedThread(RandomizeMacThread, NULL);
    if (!BeginNetworkChange()) return;
    /* v4.2: 清理残留IP */
    ClearAccumulatedIPs();
    wcsncpy(g_szExpectedIP, IP_BOSS, 63);
    ApplyIP(IP_BOSS, IP_BOSS_MASK, IP_BOSS_GW, NULL, NULL, NULL);
    LockIPReg();
    OpenNotepad();
    EndNetworkChange();
}

/* ============================================================
   清理痕迹
   ============================================================ */
static void CleanTraces(void) {
    WCHAR cmd[1024];
    WCHAR szPath[MAX_PATH];
    HKEY hKey;

    ExecHidden(L"taskkill /f /im mstsc.exe");
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Terminal Server Client\\Default");
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Terminal Server Client\\Servers");

    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath) == S_OK) {
        WCHAR szDir[MAX_PATH];
        _snwprintf(szDir, MAX_PATH-1,
            L"%ls\\Microsoft\\Terminal Server Client\\Cache", szPath);
        WCHAR szFind[MAX_PATH];
        _snwprintf(szFind, MAX_PATH-1, L"%ls\\*", szDir);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(szFind, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR szFull[MAX_PATH];
                    _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls", szDir, fd.cFileName);
                    SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(szFull);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");

    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
            0, KEY_WRITE|KEY_READ, &hKey) == ERROR_SUCCESS) {
        for (int i = 1; i <= 30; i++) {
            WCHAR v[8]; _snwprintf(v, 7, L"url%d", i);
            RegDeleteValueW(hKey, v);
        }
        RegCloseKey(hKey);
    }

    WCHAR szRecent[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, szRecent) == S_OK) {
        WCHAR szFind[MAX_PATH];
        _snwprintf(szFind, MAX_PATH-1, L"%ls\\*", szRecent);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(szFind, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR szFull[MAX_PATH];
                    _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls", szRecent, fd.cFileName);
                    SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(szFull);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath) == S_OK) {
        WCHAR szAuto[MAX_PATH];
        _snwprintf(szAuto, MAX_PATH-1,
            L"%ls\\Microsoft\\Windows\\Recent\\AutomaticDestinations", szPath);
        WCHAR szFind[MAX_PATH];
        _snwprintf(szFind, MAX_PATH-1, L"%ls\\*", szAuto);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(szFind, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR szFull[MAX_PATH];
                    _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls", szAuto, fd.cFileName);
                    SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(szFull);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    /* 清理浏览器历史（Chrome/Edge） */
    WCHAR szLocal[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, szLocal) == S_OK) {
        /* Chrome */
        _snwprintf(cmd, 1023,
            L"del /f /q \"%ls\\Google\\Chrome\\User Data\\Default\\History\"",
            szLocal);
        ExecHidden(cmd);
        _snwprintf(cmd, 1023,
            L"del /f /q \"%ls\\Google\\Chrome\\User Data\\Default\\History-journal\"",
            szLocal);
        ExecHidden(cmd);
        /* Edge */
        _snwprintf(cmd, 1023,
            L"del /f /q \"%ls\\Microsoft\\Edge\\User Data\\Default\\History\"",
            szLocal);
        ExecHidden(cmd);
        _snwprintf(cmd, 1023,
            L"del /f /q \"%ls\\Microsoft\\Edge\\User Data\\Default\\History-journal\"",
            szLocal);
        ExecHidden(cmd);
    }

    (void)cmd;
}

/* ============================================================
   窗口枚举（隐藏/显示）
   ============================================================ */
typedef struct {
    const WCHAR *title;
    BOOL bHide;
    HWND *pList;
    int  *pCount;
    int   maxCount;
} EnumWndParam;

static BOOL CALLBACK EnumWndCallback(HWND hWnd, LPARAM lParam) {
    EnumWndParam *ep = (EnumWndParam*)lParam;
    if (!IsWindowVisible(hWnd) && ep->bHide) return TRUE;
    WCHAR szTitle[512] = {0};
    GetWindowTextW(hWnd, szTitle, 511);
    if (wcsstr(szTitle, ep->title)) {
        if (ep->bHide) {
            ShowWindow(hWnd, SW_HIDE);
            if (ep->pList && ep->pCount && *ep->pCount < ep->maxCount)
                ep->pList[(*ep->pCount)++] = hWnd;
        } else {
            ShowWindow(hWnd, SW_SHOW);
        }
    }
    return TRUE;
}

static void HideProcessWindows(void) {
    g_nHiddenWnds = 0;
    if (!g_szHideList[0]) return;
    WCHAR buf[2048];
    wcsncpy(buf, g_szHideList, 2047);
    buf[2047] = 0;
    int len = (int)wcslen(buf);
    int start = 0;
    for (int i = 0; i <= len; i++) {
        if (buf[i] == L';' || buf[i] == 0) {
            buf[i] = 0;
            WCHAR *tok = buf + start;
            while (*tok == L' ') tok++;
            int tlen = (int)wcslen(tok);
            while (tlen > 0 && tok[tlen-1] == L' ') tok[--tlen] = 0;
            if (*tok) {
                EnumWndParam ep;
                ep.title    = tok;
                ep.bHide    = TRUE;
                ep.pList    = g_hiddenWnds;
                ep.pCount   = &g_nHiddenWnds;
                ep.maxCount = MAX_HIDDEN_WNDS;
                EnumWindows(EnumWndCallback, (LPARAM)&ep);
            }
            start = i + 1;
        }
    }
}

static void ShowProcessWindows(void) {
    for (int i = 0; i < g_nHiddenWnds; i++) {
        if (g_hiddenWnds[i] && IsWindow(g_hiddenWnds[i]))
            ShowWindow(g_hiddenWnds[i], SW_SHOW);
    }
    g_nHiddenWnds = 0;
    if (!g_szHideList[0]) return;
    WCHAR buf[2048];
    wcsncpy(buf, g_szHideList, 2047);
    buf[2047] = 0;
    int len = (int)wcslen(buf);
    int start = 0;
    for (int i = 0; i <= len; i++) {
        if (buf[i] == L';' || buf[i] == 0) {
            buf[i] = 0;
            WCHAR *tok = buf + start;
            while (*tok == L' ') tok++;
            int tlen = (int)wcslen(tok);
            while (tlen > 0 && tok[tlen-1] == L' ') tok[--tlen] = 0;
            if (*tok) {
                EnumWndParam ep;
                ep.title    = tok;
                ep.bHide    = FALSE;
                ep.pList    = NULL;
                ep.pCount   = NULL;
                ep.maxCount = 0;
                EnumWindows(EnumWndCallback, (LPARAM)&ep);
            }
            start = i + 1;
        }
    }
}

/* ============================================================
   热键管理
   ============================================================ */
static void RegisterHotkeys(HWND hWnd) {
    UnregisterHotKey(hWnd, HOTKEY_BOSS);
    UnregisterHotKey(hWnd, HOTKEY_SETTINGS);
    UnregisterHotKey(hWnd, HOTKEY_NETFIX);
    UnregisterHotKey(hWnd, HOTKEY_NETFIX_ALT);
    /* v4.19: HOTKEY_LOCK 已彻底删除（v4.13 锁屏功能移除后的残留宏） */
    /* v4.7: 默认修饰键组合 Ctrl+Win+Alt 由键盘钩子处理，
     * RegisterHotKey 无法注册纯修饰键组合（无字母键）。
     * 仅当用户自定义了非默认修饰键时才使用 RegisterHotKey。 */
    if (g_BossMod != DEFAULT_BOSS_MOD) {
        if (!RegisterHotKey(hWnd, HOTKEY_BOSS, g_BossMod, g_BossVk))
            WriteLog(L"RegisterHotKey BOSS failed err=%lu", GetLastError());
    } else {
        WriteLog(L"Boss hotkey using keyboard hook (pure modifier combo Ctrl+Win+Alt)");
    }
    if (!RegisterHotKey(hWnd, HOTKEY_SETTINGS, SETTINGS_MOD, SETTINGS_VK))
        WriteLog(L"RegisterHotKey SETTINGS failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_NETFIX, EMERGENCY_MOD, EMERGENCY_VK))
        WriteLog(L"RegisterHotKey NETFIX failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_NETFIX_ALT, EMERGENCY_MOD_ALT, EMERGENCY_VK_ALT))
        WriteLog(L"RegisterHotKey NETFIX_ALT failed err=%lu", GetLastError());
    /* v4.19: HOTKEY_LOCK 死代码已彻底删除 */
}

/* ============================================================
   老板键逻辑
   ============================================================ */
DWORD WINAPI BossKeyThread(LPVOID pParam) {
    BOOL bEnterBoss = (BOOL)(ULONG_PTR)pParam;
    if (bEnterBoss) {
        /* 进入老板模式：隐藏程序立即执行（用户感知快），切换IP和挂载保险筱在后台进行 */
        HideProcessWindows();   /* v4.17: 先隐藏，用户感知即刻响应 */
        CleanTraces();
        SetIPBoss();            /* IP切换在隐藏后执行 */
        VaultAutoMount();
    } else {
        /* v4.17: 退出老板模式优化：
         * 1. 先显示窗口（用户感知即刻响应）
         * 2. VaultAutoEject 和 SetIPWork 并行执行（各起一个线程）
         * 3. SetIPWork 完成后验证网络，如果不通则重试 */
        ShowProcessWindows();   /* v4.17: 先显示，用户感知快 */
        CleanTraces();
        /* VaultAutoEject 在独立线程里执行，不阻塞 IP 切换 */
        StartDetachedThread(VaultEjectThread, NULL);
        /* IP 切换并验证 */
        SetIPWork();
        /* v4.17: 验证网络是否恢复，最多重试 3 次 */
        for (int retry = 0; retry < 3; retry++) {
            Sleep(1500);
            if (AdapterHasIP(IP_WORK1)) {
                WriteLog(L"BossKeyThread: 网络已恢复，尝试 %d 次", retry + 1);
                break;
            }
            WriteLog(L"BossKeyThread: 网络未恢复，重试 %d/3", retry + 1);
            if (retry < 2) {
                /* 重新申请锁并应用IP */
                if (BeginNetworkChange()) {
                    ClearAccumulatedIPs();
                    wcsncpy(g_szExpectedIP, IP_WORK1, 63);
                    WCHAR args[512];
                    const WCHAR *adpName = GetAdapterName();
                    _snwprintf(args, 511,
                        L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls store=active",
                        adpName, IP_WORK1, IP_WORK_MASK, IP_WORK_GW);
                    RunNetshDirect(args);
                    Sleep(200);
                    EndNetworkChange();
                }
            }
        }
    }
    return 0;
}
/* v4.17: VaultAutoEject 独立线程，不阻塞 IP 切换 */
static DWORD WINAPI VaultEjectThread(LPVOID p) {
    (void)p;
    VaultAutoEject();
    return 0;
}

/* v4.19: 清理禁用 Win+L 锁屏的注册表项（提取为公用函数）
 *
 * 背景：v4.14 在 InitialIPThread 里实现了 DisableLockWorkstation 的清理，
 * 但只在启动时执行一次。如果运行中该项被重新设置（域控策略推送、
 * 第三方软件、安装旧版 BossTool 残留），Win+L 锁屏就会再次失效。
 *
 * v4.19 改进：
 * 1. 提取为独立函数 CleanupLockWorkstationPolicy，启动时 + 周期
 *    性（IPGuardThread 内 24 小时一次）都调用。
 * 2. 同时清理其他相关项：
 *    - DisableLockWorkstation（DWORD=1 直接禁用 Win+L）
 *    - NoLockScreen（Windows 10 1903+ 引入的另一种禁用方式）
 *    - DisableChangePassword（部分组策略模板会附带）
 * 3. 使用两种方式确保删除：
 *    a. 直接 RegDeleteValueW（程序已管理员权限）
 *    b. 备用 reg.exe 命令（兼容权限错误场景，静默执行）
 *
 * 注意：HKLM 下的策略键如果被域控推送，本机管理员可能没有写权限。
 * 这种情况下 reg.exe 也会失败（这是 Windows 安全设计，不是 bug）。
 * 这种情况用户需要联系 IT 部门解除策略。 */
static void CleanupLockWorkstationPolicy(void) {
    HKEY hKey;
    BOOL bAnyDeleted = FALSE;
    LPCWSTR rgValuesToDelete[] = {
        L"DisableLockWorkstation",
        L"NoLockScreen",
        L"DisableChangePassword",
        NULL
    };

    /* 方式1: 直接 API 删除 */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        for (int i = 0; rgValuesToDelete[i]; i++) {
            if (RegDeleteValueW(hKey, rgValuesToDelete[i]) == ERROR_SUCCESS) {
                bAnyDeleted = TRUE;
                WriteLog(L"v4.19: 已删除注册表项 %ls", rgValuesToDelete[i]);
            }
        }
        RegCloseKey(hKey);
    }

    /* 方式2: 备用 reg delete 命令（兼容权限/路径异常） */
    for (int i = 0; rgValuesToDelete[i]; i++) {
        WCHAR szCmd[256];
        _snwprintf(szCmd, 255,
            L"reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v %ls /f",
            rgValuesToDelete[i]);
        ExecHidden(szCmd);
    }

    if (!bAnyDeleted) {
        WriteLog(L"v4.19: 注册表项无需清理（不存在或权限不足）");
    }
}

DWORD WINAPI InitialIPThread(LPVOID pParam) {
    (void)pParam;

    /* v4.19: 启动时清理 Win+L 锁屏策略项。
     * 详见 CleanupLockWorkstationPolicy() 函数注释。 */
    CleanupLockWorkstationPolicy();

    /* v3.5: 启动时扫描并卸载旧版遗留的VHDX（更换版本后第一次运行） */
    VaultRecoverAndEject();
    SetIPWork();
    return 0;
}

/* v4.19.2: SetIPWorkThread wrapper — 让 SetIPWork 能在 detached thread 中运行
 * 用于退出按钮异步化：用户点退出时不阻塞主线程 */
static DWORD WINAPI SetIPWorkThread(LPVOID p) {
    (void)p;
    SetIPWork();
    return 0;
}

static void DoBossKey(void) {
    if (!g_bBossMode) {
        InterlockedExchange((LONG*)&g_bBossMode, TRUE);
        StartDetachedThread(BossKeyThread, (LPVOID)(ULONG_PTR)TRUE);
    } else {
        InterlockedExchange((LONG*)&g_bBossMode, FALSE);
        StartDetachedThread(BossKeyThread, (LPVOID)(ULONG_PTR)FALSE);
    }
}

/* ============================================================
   键盘钩子
   ============================================================ */
LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0) {
        /* v4.19: 钩子被 Windows 跳过计数（环境变量启用时记录） */
        if (g_bHookDebug) {
            DWORD cnt = (DWORD)InterlockedIncrement((LONG*)&s_dwHookSkipCount);
            if ((cnt & 0x3F) == 1) {  /* 每 64 次写一次，避免日志爆炸 */
                WriteLog(L"[HOOK] nCode<0 跳过累计 %lu 次", cnt);
            }
        }
        return CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
    }

    KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT*)lParam;
    UINT vk = kb->vkCode;
    BOOL bDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);

    /* v4.19: 状态卡死自愈 — 检测时间戳超时的修饰键状态，自动重置。
     * 见 s_dwModCtrlTime/s_dwModAltTime/s_dwModWinTime 定义处的注释。
     * 关键场景：用户快速 Alt+Tab 切窗口时 Ctrl/Alt UP 事件被 LL 钩子
     * 超时跳过，s_bModCtrl/s_bModAlt 卡在 TRUE → 下次按 Win+L 闪烁。
     */
    {
        DWORD dwNow = GetTickCount();
        if (s_bModCtrl && s_dwModCtrlTime != 0 &&
            (dwNow - s_dwModCtrlTime) > MOD_STALE_MS) {
            DWORD stale = (dwNow - s_dwModCtrlTime) / 1000;
            s_bModCtrl = FALSE;
            s_dwModCtrlTime = 0;
            s_bBossComboTriggered = FALSE;
            if (g_bHookDebug)
                WriteLog(L"[HOOK] Ctrl 状态卡死自愈 (超时 %lu 秒)", stale);
        }
        if (s_bModAlt && s_dwModAltTime != 0 &&
            (dwNow - s_dwModAltTime) > MOD_STALE_MS) {
            DWORD stale = (dwNow - s_dwModAltTime) / 1000;
            s_bModAlt = FALSE;
            s_dwModAltTime = 0;
            s_bBossComboTriggered = FALSE;
            if (g_bHookDebug)
                WriteLog(L"[HOOK] Alt 状态卡死自愈 (超时 %lu 秒)", stale);
        }
        if (s_bModWin && s_dwModWinTime != 0 &&
            (dwNow - s_dwModWinTime) > MOD_STALE_MS) {
            DWORD stale = (dwNow - s_dwModWinTime) / 1000;
            s_bModWin = FALSE;
            s_dwModWinTime = 0;
            s_bBossComboTriggered = FALSE;
            if (g_bHookDebug)
                WriteLog(L"[HOOK] Win 状态卡死自愈 (超时 %lu 秒)", stale);
        }
    }

    /* v4.9: 用局部状态变量跟踪修饰键状态，而不依赖 GetAsyncKeyState。
     * GetAsyncKeyState 在低级键盘钩子回调中存在时序问题：
     * 当 Alt 键触发 WM_SYSKEYDOWN 时，GetAsyncKeyState(VK_MENU) 可能还没有更新，
     * 导致三键同时按下时判断失败。
     *
     * v4.19: 同时记录时间戳，供上面超时自愈逻辑使用。 */
    if (vk == VK_LCONTROL || vk == VK_RCONTROL) {
        s_bModCtrl = bDown;
        if (bDown) s_dwModCtrlTime = GetTickCount();
        else { s_dwModCtrlTime = 0; s_bBossComboTriggered = FALSE; }
        if (g_bHookDebug)
            WriteLog(L"[HOOK] Ctrl %lc 0x%02X %s",
                (vk == VK_LCONTROL ? L'L' : L'R'), vk, bDown ? L"DOWN" : L"UP");
    } else if (vk == VK_LMENU || vk == VK_RMENU) {
        s_bModAlt = bDown;
        if (bDown) s_dwModAltTime = GetTickCount();
        else { s_dwModAltTime = 0; s_bBossComboTriggered = FALSE; }
        if (g_bHookDebug)
            WriteLog(L"[HOOK] Alt %lc 0x%02X %s",
                (vk == VK_LMENU ? L'L' : L'R'), vk, bDown ? L"DOWN" : L"UP");
    } else if (vk == VK_LWIN || vk == VK_RWIN) {
        s_bModWin = bDown;
        if (bDown) s_dwModWinTime = GetTickCount();
        else { s_dwModWinTime = 0; s_bBossComboTriggered = FALSE; }
        if (g_bHookDebug)
            WriteLog(L"[HOOK] Win %lc 0x%02X %s (Ctrl=%d Alt=%d)",
                (vk == VK_LWIN ? L'L' : L'R'), vk, bDown ? L"DOWN" : L"UP",
                (int)s_bModCtrl, (int)s_bModAlt);
    }

    /* v4.13: 删除锁屏功能， Win+L 不再拦截，正常传递给系统 */

    /* v4.19: Ctrl+Win+Alt 三键同时按下即触发老板键。
     * 完全使用 s_bModCtrl/s_bModWin/s_bModAlt（v4.16 之后已经一致），
     * 修复合并 v4.9 的 bCtrl/bAlt/bWin 局部副本可能与更新后的 s_*
     * 不一致的潜在 bug（虽然之前 v4.16 已规避，但用全局更稳）。
     * 三键中任意一键按下时，检查另两键是否已按着，满足则触发。
     * 同时吃掉 Win 键事件防止开始菜单弹出。 */
    if (g_BossMod == DEFAULT_BOSS_MOD) {
        /* v4.16: 只在 Ctrl+Win+Alt 三键全部同时按着时才吃掉 Win 键（防开始菜单）。
         * 之前的逻辑是"Ctrl 或 Alt 任意一个按着就吃掉 Win 键"，
         * 这会导致 Win+L 时如果 s_bModCtrl/s_bModAlt 因上次操作遗留为 TRUE，
         * Win 键事件被吃掉，系统收不到完整的 Win+L → 屏幕疯狂闪烁。
         * 新逻辑：必须三键全部同时按着才吃掉 Win 键，Win+L 绝不受影响。
         *
         * v4.19: 同时配合上面的超时自愈，即使 s_bModCtrl/s_bModAlt 真的
         * 卡住，5秒后也会被自动重置，Win+L 永远不会被误拦截。 */
        if ((vk == VK_LWIN || vk == VK_RWIN) && s_bModCtrl && s_bModAlt) {
            /* 三键全部按着，吃掉 Win 键防止开始菜单 */
            if (g_bHookDebug)
                WriteLog(L"[HOOK] 吃掉 Win 键（三键全按，触发老板键）");
            return 1;
        }
        /* 三键同时按下 → 触发老板键 */
        if (bDown && s_bModCtrl && s_bModWin && s_bModAlt && !s_bBossComboTriggered) {
            s_bBossComboTriggered = TRUE;
            if (g_bHookDebug)
                WriteLog(L"[HOOK] 老板键触发 vk=0x%02X", vk);
            DoBossKey();
            return 1;
        }
    }

    /* v4.15: 锁屏功能已彻底删除，此处不再拦截任何键盘事件 */

    return CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
}

/* v4.15: 锁屏界面代码已彻底删除 */


/* ============================================================
   登录对话框
   ============================================================ */
LRESULT CALLBACK LoginWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    switch(msg) {
    case WM_CREATE: {
        HFONT hF=(HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HWND h;
        h=CreateWindowW(L"STATIC",L"请输入访问密码:",
            WS_CHILD|WS_VISIBLE,15,15,200,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"EDIT",L"",
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            15,40,220,24,hWnd,(HMENU)IDC_LOGIN_PWD,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"BUTTON",L"确定",
            WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
            15,76,90,28,hWnd,(HMENU)IDC_LOGIN_OK,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"BUTTON",L"取消",
            WS_CHILD|WS_VISIBLE,
            135,76,90,28,hWnd,(HMENU)IDC_LOGIN_CANCEL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        SetFocus(GetDlgItem(hWnd,IDC_LOGIN_PWD));
        break;
    }
    case WM_COMMAND:
        if(LOWORD(wParam)==IDC_LOGIN_OK||LOWORD(wParam)==IDOK) {
            WCHAR pwd[64]={0};
            GetDlgItemTextW(hWnd,IDC_LOGIN_PWD,pwd,63);
            if(wcscmp(pwd,g_szLoginPwd)==0) {
                DestroyWindow(hWnd);
                g_hWndLogin=NULL;
                ShowSettingsWindow();
            } else {
                MessageBoxW(hWnd,L"密码错误！",L"错误",MB_OK|MB_ICONERROR);
                SetDlgItemTextW(hWnd,IDC_LOGIN_PWD,L"");
                SetFocus(GetDlgItem(hWnd,IDC_LOGIN_PWD));
            }
        } else if(LOWORD(wParam)==IDC_LOGIN_CANCEL) {
            DestroyWindow(hWnd);
            g_hWndLogin=NULL;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        g_hWndLogin=NULL;
        break;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

static void ShowLoginDialog(void) {
    if(g_hWndLogin && IsWindow(g_hWndLogin)) {
        SetForegroundWindow(g_hWndLogin);
        return;
    }
    if(g_hWndSettings && IsWindow(g_hWndSettings))
        ShowWindow(g_hWndSettings,SW_HIDE);

    WNDCLASSW wc={0};
    wc.lpfnWndProc   = LoginWndProc;
    wc.hInstance     = g_hInst;
    wc.lpszClassName = L"BossToolLogin";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
    RegisterClassW(&wc);

    int cx=GetSystemMetrics(SM_CXSCREEN);
    int cy=GetSystemMetrics(SM_CYSCREEN);
    g_hWndLogin=CreateWindowExW(
        WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
        L"BossToolLogin",L"系统设置 - 身份验证",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,
        (cx-270)/2,(cy-150)/2,270,150,
        NULL,NULL,g_hInst,NULL);
    ShowWindow(g_hWndLogin,SW_SHOW);
    UpdateWindow(g_hWndLogin);
    SetForegroundWindow(g_hWndLogin);
}

/* ============================================================
   v3.3: 设置窗口（含隐私保险箱区域）
   ============================================================ */
static const WCHAR *g_szModNames[] = {
    L"Ctrl+Alt", L"Ctrl+Shift", L"Alt+Shift", L"Ctrl+Alt+Shift", L"Ctrl+Win+Alt"
};
static const UINT g_nModVals[] = {
    MOD_CONTROL|MOD_ALT,
    MOD_CONTROL|MOD_SHIFT,
    MOD_ALT|MOD_SHIFT,
    MOD_CONTROL|MOD_ALT|MOD_SHIFT,
    MOD_CONTROL|MOD_WIN|MOD_ALT
};

LRESULT CALLBACK SettingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    switch(msg) {
    case WM_CREATE: {
        HFONT hF=(HFONT)GetStockObject(DEFAULT_GUI_FONT);
        int y=8;
        HWND h;

        /* 登录密码 */
        h=CreateWindowW(L"STATIC",L"启动登录密码:",
            WS_CHILD|WS_VISIBLE,8,y,120,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"EDIT",g_szLoginPwd,
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
            135,y,230,22,hWnd,(HMENU)IDC_SET_LPWD,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=28;

        /* v4.13: 锁屏功能已删除，锁屏密码输入框不再显示 */

        /* 老板键修饰符 */
        h=CreateWindowW(L"STATIC",L"老板键修饰符:",
            WS_CHILD|WS_VISIBLE,8,y,120,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"COMBOBOX",NULL,
            WS_CHILD|WS_VISIBLE|WS_BORDER|CBS_DROPDOWNLIST,
            135,y,160,100,hWnd,(HMENU)IDC_SET_BMOD,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        for(int i=0;i<5;i++)
            SendMessageW(h,CB_ADDSTRING,0,(LPARAM)g_szModNames[i]);
        int selM=0;
        for(int i=0;i<5;i++) if(g_nModVals[i]==g_BossMod){selM=i;break;}
        SendMessage(h,CB_SETCURSEL,selM,0);
        y+=28;

        /* 老板键按键（当选择 Ctrl+Win+Alt 时该框无效） */
        h=CreateWindowW(L"STATIC",L"老板键(字母/数字):",
            WS_CHILD|WS_VISIBLE,8,y,130,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        WCHAR szVk[4]={(WCHAR)g_BossVk,0};
        h=CreateWindowW(L"EDIT",szVk,
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_UPPERCASE,
            145,y,50,22,hWnd,(HMENU)IDC_SET_BVK,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessage(h,EM_SETLIMITTEXT,1,0);
        /* v4.9: 当选择 Ctrl+Win+Alt 时，字母键无效，禁用输入框 */
        if (g_BossMod == DEFAULT_BOSS_MOD) {
            EnableWindow(h, FALSE);
            SetDlgItemTextW(hWnd, IDC_SET_BVK, L"-");
        }
        y+=28;

        /* 开机自启 */
        h=CreateWindowW(L"BUTTON",L"开机自动运行",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
            8,y,200,22,hWnd,(HMENU)IDC_SET_AR,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessage(h,BM_SETCHECK,g_bAutoRun?BST_CHECKED:BST_UNCHECKED,0);
        y+=30;

        /* 隐藏列表 */
        h=CreateWindowW(L"STATIC",
            L"老板键隐藏程序(窗口标题关键词，分号分隔，支持中文):",
            WS_CHILD|WS_VISIBLE,8,y,370,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=22;
        h=CreateWindowW(L"EDIT",g_szHideList,
            WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|
            ES_AUTOHSCROLL|ES_MULTILINE,
            8,y,370,55,hWnd,(HMENU)IDC_SET_HL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=62;

        /* 提示 */
        h=CreateWindowW(L"STATIC",
            L"提示：隐藏列表支持部分匹配，如\"记事本\"可匹配\"无标题 - 记事本\"",
            WS_CHILD|WS_VISIBLE,8,y,370,18,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=24;

        /* 允许修改IP */
        h=CreateWindowW(L"BUTTON",L"允许手动修改IP地址（关闭时自动锁定）",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
            8,y,280,22,hWnd,(HMENU)IDC_SET_ALLOWIP,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessage(h,BM_SETCHECK,g_bAllowIPChange?BST_CHECKED:BST_UNCHECKED,0);
        y+=30;

        /* ---- 隐私保险箱分隔线 ---- */
        h=CreateWindowW(L"STATIC",L"——————————— 隐私保险箱（VHDX/BitLocker） ———————————",
            WS_CHILD|WS_VISIBLE,8,y,370,18,hWnd,(HMENU)IDC_VAULT_LABEL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=22;

        /* 伪装文件路径 */
        h=CreateWindowW(L"STATIC",L"伪装文件(.lvm)路径:",
            WS_CHILD|WS_VISIBLE,8,y,130,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"EDIT",g_szVaultPath,
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
            8,y+22,280,22,hWnd,(HMENU)IDC_VAULT_PATH,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"BUTTON",L"浏览...",
            WS_CHILD|WS_VISIBLE,
            295,y+22,80,22,hWnd,(HMENU)IDC_VAULT_BROWSE,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=50;

        /* BitLocker 密码 */
        h=CreateWindowW(L"STATIC",L"BitLocker密码:",
            WS_CHILD|WS_VISIBLE,8,y,100,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"EDIT",g_szVaultPwd,
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            115,y,160,22,hWnd,(HMENU)IDC_VAULT_PWD,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=30;

        /* 测试挂载 / 手动弹出 按钮 */
        h=CreateWindowW(L"BUTTON",L"测试挂载",
            WS_CHILD|WS_VISIBLE,
            8,y,100,26,hWnd,(HMENU)IDC_VAULT_TEST,g_hInst
,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"BUTTON",L"手动弹出",
            WS_CHILD|WS_VISIBLE,
            115,y,100,26,hWnd,(HMENU)IDC_VAULT_EJECT,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=30;

        /* 提示文字 */
        h=CreateWindowW(L"STATIC",
            L"提示：选择.lvm文件（实为.vhdx），老板键进入时自动挂载，退出时\r\n自动弹出并清除痕迹",
            WS_CHILD|WS_VISIBLE,8,y,370,32,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=38;

        /* 底部按钮行 */
        h=CreateWindowW(L"BUTTON",L"立即应用工作IP",
            WS_CHILD|WS_VISIBLE,
            8,y,130,28,hWnd,(HMENU)IDC_SET_APPLYIP,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"BUTTON",L"保存并隐藏",
            WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
            155,y,110,28,hWnd,(HMENU)IDC_SET_SAVE,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"BUTTON",L"关闭",
            WS_CHILD|WS_VISIBLE,
            275,y,80,28,hWnd,(HMENU)IDC_SET_CLOSE,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        /* v4.18: 退出程序按鈕 */
        y+=34;
        h=CreateWindowW(L"BUTTON",L"退出程序（当前处于老板模式时会先恢复IP）",
            WS_CHILD|WS_VISIBLE,
            8,y,360,28,hWnd,(HMENU)IDC_SET_EXIT,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        break;
    }
    case WM_COMMAND: {
        int id=LOWORD(wParam);

        if(id==IDC_VAULT_BROWSE) {
            /* 打开文件选择对话框，选择 .lvm 文件 */
            OPENFILENAMEW ofn;
            WCHAR szFile[MAX_PATH] = {0};
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner   = hWnd;
            ofn.lpstrFilter = L"伪装文件 (*.lvm)\0*.lvm\0所有文件 (*.*)\0*.*\0";
            ofn.lpstrFile   = szFile;
            ofn.nMaxFile    = MAX_PATH;
            ofn.lpstrTitle  = L"选择伪装文件（实为VHDX）";
            ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if(GetOpenFileNameW(&ofn)) {
                SetDlgItemTextW(hWnd, IDC_VAULT_PATH, szFile);
            }
        } else if(id==IDC_VAULT_TEST) {
            /* 测试挂载：先读取当前界面输入 */
            GetDlgItemTextW(hWnd, IDC_VAULT_PATH, g_szVaultPath, MAX_PATH-1);
            GetDlgItemTextW(hWnd, IDC_VAULT_PWD,  g_szVaultPwd,  127);
            if(!g_szVaultPath[0]) {
                MessageBoxW(hWnd, L"请先填写伪装文件路径！", L"提示",
                            MB_OK|MB_ICONWARNING);
                break;
            }
            if(!g_szVaultPwd[0]) {
                MessageBoxW(hWnd, L"请先填写 BitLocker 密码！", L"提示",
                            MB_OK|MB_ICONWARNING);
                break;
            }
            VaultMount(hWnd);
        } else if(id==IDC_VAULT_EJECT) {
            VaultEject(hWnd);
        } else if(HIWORD(wParam)==CBN_SELCHANGE && id==IDC_SET_BMOD) {
            /* v4.9: 下拉菜单切换时实时更新字母键输入框状态 */
            int selNow=(int)SendDlgItemMessageW(hWnd,IDC_SET_BMOD,CB_GETCURSEL,0,0);
            HWND hVk=GetDlgItem(hWnd,IDC_SET_BVK);
            if(selNow>=0 && selNow<5 && g_nModVals[selNow]==DEFAULT_BOSS_MOD) {
                EnableWindow(hVk, FALSE);
                SetDlgItemTextW(hWnd, IDC_SET_BVK, L"-");
            } else {
                EnableWindow(hVk, TRUE);
                WCHAR szVkTmp[4]={(WCHAR)g_BossVk,0};
                SetDlgItemTextW(hWnd, IDC_SET_BVK, szVkTmp);
            }
        } else if(id==IDC_SET_SAVE) {
            /* 读取所有设置 */
            GetDlgItemTextW(hWnd,IDC_SET_LPWD,g_szLoginPwd,63);
            /* v4.13: 锁屏功能已删除，不再读取锁屏密码 */
            GetDlgItemTextW(hWnd,IDC_SET_HL,g_szHideList,2047);
            int sel=(int)SendDlgItemMessageW(hWnd,IDC_SET_BMOD,CB_GETCURSEL,0,0);
            if(sel>=0&&sel<5) g_BossMod=g_nModVals[sel];
            WCHAR szVk[4]={0};
            /* v4.9: 当选择 Ctrl+Win+Alt 时，字母键不读取（无效） */
            if(g_BossMod != DEFAULT_BOSS_MOD) {
                GetDlgItemTextW(hWnd,IDC_SET_BVK,szVk,3);
                if((szVk[0]>='A'&&szVk[0]<='Z')||(szVk[0]>='0'&&szVk[0]<='9'))
                    g_BossVk=szVk[0];
            }
            g_bAutoRun=(SendDlgItemMessage(hWnd,IDC_SET_AR,BM_GETCHECK,0,0)==BST_CHECKED);
            BOOL bAllow=(SendDlgItemMessage(hWnd,IDC_SET_ALLOWIP,BM_GETCHECK,0,0)==BST_CHECKED);
            if(bAllow != g_bAllowIPChange) {
                g_bAllowIPChange = bAllow;
                if(!bAllow) { LockIPReg(); if(g_bBossMode) SetIPBoss(); else SetIPWork(); }
                else UnlockIPReg();
            }
            /* 读取保险箱设置 */
            GetDlgItemTextW(hWnd, IDC_VAULT_PATH, g_szVaultPath, MAX_PATH-1);
            GetDlgItemTextW(hWnd, IDC_VAULT_PWD,  g_szVaultPwd,  127);

            SaveConfig();
            SetAutoRun(g_bAutoRun);
            UnregisterHotKey(g_hWndMain,HOTKEY_BOSS);
            UnregisterHotKey(g_hWndMain,HOTKEY_SETTINGS);
            UnregisterHotKey(g_hWndMain,HOTKEY_NETFIX);
            RegisterHotkeys(g_hWndMain);
            MessageBoxW(hWnd,L"设置已保存！程序继续在后台运行。",L"提示",MB_OK);
            ShowWindow(hWnd,SW_HIDE);
        } else if(id==IDC_SET_CLOSE) {
            ShowWindow(hWnd,SW_HIDE);
        } else if(id==IDC_SET_APPLYIP) {
            SetIPWork();
            MessageBoxW(hWnd,L"工作IP已应用！",L"提示",MB_OK);
        } else if(id==IDC_SET_EXIT) {
            /* v4.18: 退出程序
             * v4.19.2: 异步化 SetIPWork，避免主线程卡住永远到不了 DestroyWindow。
             * 之前的 bug：如果老板模式时点退出，主线程同步调用 SetIPWork，
             *          而 SetIPWork 包含 Sleep(2000) + 切换网卡，如果网络
             *          有问题可能阻塞数十秒，导致用户感觉"程序没反应"。 */
            int ret = MessageBoxW(hWnd,
                L"确定要退出 BossTool 吗？\r\n如果当前处于老板模式，退出前会自动恢复工作IP。",
                L"退出确认", MB_YESNO | MB_ICONQUESTION);
            if (ret == IDYES) {
                /* 关闭设置窗口 */
                ShowWindow(hWnd, SW_HIDE);
                /* 退出主程序（不阻塞） */
                DestroyWindow(g_hWndMain);
                /* v4.19.2: 如果在老板模式，异步恢复工作IP（不等它完成） */
                if (g_bBossMode) {
                    InterlockedExchange((LONG*)&g_bBossMode, FALSE);
                    /* 用 detached thread 异步恢复网络，避免阻塞进程退出 */
                    typedef DWORD (WINAPI *PFN_START_THREAD)(LPVOID);
                    /* StartDetachedThread 已经在前面定义 */
                    StartDetachedThread((LPTHREAD_START_ROUTINE)
                        (void*)SetIPWorkThread, (LPVOID)0);
                }
            }
        }
        break;
    }
    case WM_CLOSE:
        ShowWindow(hWnd,SW_HIDE);
        return 0;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

static void ShowSettingsWindow(void) {
    if(!g_hWndSettings) {
        WNDCLASSW wc={0};
        wc.lpfnWndProc   = SettingsWndProc;
        wc.hInstance     = g_hInst;
        wc.lpszClassName = L"BossToolSettings";
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
        wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
        RegisterClassW(&wc);

        int cx=GetSystemMetrics(SM_CXSCREEN);
        int cy=GetSystemMetrics(SM_CYSCREEN);
        /* v3.3: 窗口高度增加以容纳保险箱区域 */
        g_hWndSettings=CreateWindowExW(
            WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
            L"BossToolSettings",L"系统设置",
            WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,
            (cx-400)/2,(cy-625)/2,400,625,  /* v4.18: +45px 容纳退出按鈕 */
            NULL,NULL,g_hInst,NULL);
    } else {
        /* 刷新控件内容 */
        SetDlgItemTextW(g_hWndSettings,IDC_SET_LPWD,g_szLoginPwd);
        /* v4.13: 锁屏密码输入框已删除 */
        SetDlgItemTextW(g_hWndSettings,IDC_SET_HL,g_szHideList);
        WCHAR szVk[4]={(WCHAR)g_BossVk,0};
        /* v4.9: 当选择 Ctrl+Win+Alt 时禁用字母键输入框 */
        if (g_BossMod == DEFAULT_BOSS_MOD) {
            SetDlgItemTextW(g_hWndSettings,IDC_SET_BVK,L"-");
            EnableWindow(GetDlgItem(g_hWndSettings,IDC_SET_BVK), FALSE);
        } else {
            SetDlgItemTextW(g_hWndSettings,IDC_SET_BVK,szVk);
            EnableWindow(GetDlgItem(g_hWndSettings,IDC_SET_BVK), TRUE);
        }
        int selM=0;
        for(int i=0;i<5;i++) if(g_nModVals[i]==g_BossMod){selM=i;break;};
        SendDlgItemMessageW(g_hWndSettings,IDC_SET_BMOD,CB_SETCURSEL,selM,0);
        SendDlgItemMessage(g_hWndSettings,IDC_SET_AR,BM_SETCHECK,
                           g_bAutoRun?BST_CHECKED:BST_UNCHECKED,0);
        SendDlgItemMessage(g_hWndSettings,IDC_SET_ALLOWIP,BM_SETCHECK,
                           g_bAllowIPChange?BST_CHECKED:BST_UNCHECKED,0);
        /* 刷新保险箱控件 */
        SetDlgItemTextW(g_hWndSettings,IDC_VAULT_PATH,g_szVaultPath);
        SetDlgItemTextW(g_hWndSettings,IDC_VAULT_PWD,g_szVaultPwd);
    }
    ShowWindow(g_hWndSettings,SW_SHOW);
    UpdateWindow(g_hWndSettings);
    SetForegroundWindow(g_hWndSettings);
}

/* ============================================================
   主窗口
   ============================================================ */
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
    case WM_HOTKEY:
        if(wParam==HOTKEY_BOSS) {
            DoBossKey();
        } else if(wParam==HOTKEY_SETTINGS) {
            ShowLoginDialog();
        } else if(wParam==HOTKEY_NETFIX || wParam==HOTKEY_NETFIX_ALT) {
            StartDetachedThread(EmergencyFixThread, NULL);
        }
        break;
    /* v4.19: WM_LOCK_SCREEN / WM_TRAY_ICON 已彻底删除（宏和处理函数一并清理） */
    case WM_BOSS_KEY:
        if (!g_bBossMode) DoBossKey();
        break;
    case WM_SHOW_SETTINGS:
        ShowSettingsWindow();
        break;
    /* v4.18: 托盘图标消息处理 — v4.19 删除（托盘图标从未实际添加） */
    case WM_COMMAND:
        /* v4.19: IDM_TRAY_* 死代码已清理 — 托盘图标从未添加。 */
        break;
    case WM_DESTROY:
        /* v4.19: 死代码已清理 — 托盘图标从未实际添加（NIM_ADD 从未调用），
         * 因此 WM_DESTROY 里的 NIM_DELETE 是无效操作。 */
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

/* ============================================================
   提权
   ============================================================ */
static BOOL IsElevated(void) {
    BOOL b=FALSE;
    HANDLE hToken=NULL;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hToken)) {
        TOKEN_ELEVATION te; DWORD sz;
        if(GetTokenInformation(hToken,TokenElevation,&te,sizeof(te),&sz))
            b=te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return b;
}

static void RelaunchAsAdmin(void) {
    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(NULL,szPath,MAX_PATH);
    SHELLEXECUTEINFOW sei={0};
    sei.cbSize=sizeof(sei);
    sei.lpVerb=L"runas";
    sei.lpFile=szPath;
    sei.nShow=SW_HIDE;
    sei.fMask=SEE_MASK_NOCLOSEPROCESS;
    ShellExecuteExW(&sei);
}

/* ============================================================
   WinMain
   ============================================================ */
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInst,
                    LPWSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInst; (void)lpCmdLine; (void)nCmdShow;
    g_hInst=hInstance;

    /* 单实例 */
    g_hMutex=CreateMutexW(NULL,TRUE,APP_MUTEX_NAME);
    if(GetLastError()==ERROR_ALREADY_EXISTS) {
        if(g_hMutex) CloseHandle(g_hMutex);
        return 0;
    }

    /* 提权 */
    if(!IsElevated()) {
        RelaunchAsAdmin();
        if(g_hMutex) CloseHandle(g_hMutex);
        return 0;
    }

    /* 初始化 */
    INITCOMMONCONTROLSEX icc={sizeof(icc),ICC_WIN95_CLASSES};
    InitCommonControlsEx(&icc);
    srand((unsigned)time(NULL));

    /* 加载配置（含保险箱配置） */
    LoadConfig();

    /* 进程保护 */
    ProtectProcess();

    /* 启动守护线程 */
    /* v4.13: 锁屏功能已删除，不再启动 WatchdogThread/GuardThread */
    StartDetachedThread(IPGuardThread, NULL);

    /* 注册主窗口 */
    WNDCLASSW wc={0};
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = L"BossToolMain";
    RegisterClassW(&wc);

    g_hWndMain=CreateWindowExW(0,
        L"BossToolMain",L"",
        WS_OVERLAPPEDWINDOW,
        0,0,0,0,NULL,NULL,hInstance,NULL);
    ShowWindow(g_hWndMain,SW_HIDE);

    /* 安装键盘钩子 */
    g_hKeyHook=SetWindowsHookExW(WH_KEYBOARD_LL,
                                  KeyboardHookProc,
                                  hInstance,0);

    /* v4.19: 检查 BOSS_KEYHOOK_DEBUG 环境变量启用诊断日志
     * 见 g_bHookDebug 定义处的说明。 */
    {
        WCHAR szDebug[8] = {0};
        if (GetEnvironmentVariableW(L"BOSS_KEYHOOK_DEBUG", szDebug, 7) > 0 &&
            (szDebug[0] == L'1' || szDebug[0] == L'y' || szDebug[0] == L'Y' ||
             _wcsicmp(szDebug, L"true") == 0)) {
            InterlockedExchange((LONG*)&g_bHookDebug, TRUE);
            WriteLog(L"v4.19: BOSS_KEYHOOK_DEBUG 已启用 — 详细日志写入 %%TEMP%%\\bosstool.log");
        }
    }

    /* 注册热键 */
    RegisterHotkeys(g_hWndMain);

    /* 启动时设置工作IP */
    StartDetachedThread(InitialIPThread, NULL);

    /* 判断是否开机自启 */
    BOOL bAutoStart = (wcsstr(lpCmdLine, L"/autostart") != NULL);
    if (!bAutoStart) {
        ShowLoginDialog();
    }

    /* 消息循环 */
    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* 清理：退出时弹出保险箱 */
    if(g_bVaultMounted) VaultEject(NULL);

    if(g_hKeyHook) UnhookWindowsHookEx(g_hKeyHook);
    UnregisterHotKey(g_hWndMain,HOTKEY_BOSS);
    UnregisterHotKey(g_hWndMain,HOTKEY_SETTINGS);
    UnregisterHotKey(g_hWndMain,HOTKEY_NETFIX);
    UnregisterHotKey(g_hWndMain,HOTKEY_NETFIX_ALT);
    UnlockIPReg();
    if(g_hMutex) CloseHandle(g_hMutex);
    return (int)msg.wParam;
}
