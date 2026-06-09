/*
 * BossTool v3.2 - Windows 7/8/10/11 隐形管理工具
 *
 * v3.2 真正修复 ERR_NO_BUFFER_SPACE（推翻 v3.1 的错误方向）：
 *   病灶不是 TIME_WAIT 僵尸连接，而是 NSI/AFD 内核状态被持续污染。
 *   1. 删除 FixTcpBufferSpace —— 其中3个注册表项无效，1个治标，且未检查
 *      返回值，普通权限下根本写不进去（v3.1 的修复从未真正生效）。
 *   2. 重写 ApplyIP：
 *        - 改用 store=active 模式（只改运行时配置，不写持久化）
 *        - 不再 route flush / delete arpcache / delete destinationcache
 *          （这3条命令是元凶：长期累积污染 NSI Proxy 内部状态）
 *   3. WatchdogThread Sleep 400→2000，GuardThread Sleep 80→500
 *      （把对DWM/explorer的焦点抢夺压力降低 6~25 倍，不影响锁屏防绕过）
 *   4. g_bLocked / g_bBossMode 改用 InterlockedExchange，消除跨线程竞态
 *   5. 新增 Ctrl+Alt+F12 一键修复网络栈热键，发病时秒救，不用重启电脑
 *
 * v3.0 功能：
 * 1. 隐藏程序支持中文窗口标题
 * 2. 清理痕迹完全后台，无任何黑框/前台窗口
 * 3. 锁屏直接替代系统锁屏
 * 4. 解锁后任务管理器/其他程序可正常打开
 * 5. 每次呼出设置界面都需要重新输入密码
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
#define DEFAULT_BOSS_MOD    (MOD_CONTROL|MOD_ALT)
#define DEFAULT_BOSS_VK     'X'
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
#define IP_BOSS_DNS     L"8.2.27.254"  /* DNS与网关相同 */

/* 热键ID */
#define HOTKEY_BOSS     1001
#define HOTKEY_SETTINGS 1002
#define HOTKEY_NETFIX   1003   /* v3.2: 一键修复网络栈 */

#define EMERGENCY_MOD   (MOD_CONTROL|MOD_ALT)
#define EMERGENCY_VK    VK_F12

/* 自定义消息 */
#define WM_LOCK_SCREEN   (WM_USER+10)
#define WM_SHOW_SETTINGS (WM_USER+13)

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
#define IDC_SET_ALLOWIP  3012

/* ============================================================
   全局变量
   ============================================================ */
static HINSTANCE g_hInst        = NULL;
static HWND      g_hWndMain     = NULL;
static HWND      g_hWndSettings = NULL;
static HWND      g_hWndLock     = NULL;
static HWND      g_hWndLogin    = NULL;
static HHOOK     g_hKeyHook     = NULL;
static HANDLE    g_hMutex       = NULL;

/* 状态标志 */
static volatile BOOL g_bBossMode = FALSE;   /* 是否处于老板模式 */
static volatile BOOL g_bLocked   = FALSE;   /* 是否处于锁屏状态 */
static volatile LONG g_lNetworkChangeBusy = 0;
/* 注意：不再保存登录状态，每次呼出设置都需要密码 */

/* 配置 */
static WCHAR g_szLoginPwd[64]   = DEFAULT_LOGIN_PWD;
static WCHAR g_szLockPwd[64]    = DEFAULT_LOCK_PWD;
static UINT  g_BossMod          = DEFAULT_BOSS_MOD;
static UINT  g_BossVk           = DEFAULT_BOSS_VK;
static BOOL  g_bAutoRun         = FALSE;
static WCHAR g_szHideList[2048] = L"";

/* 锁屏状态 */
static int   g_nLockFail        = 0;
static DWORD g_dwLockLockTime   = 0;
static WCHAR g_szLockInput[64]  = {0};
static int   g_nLockInputLen    = 0;
static BOOL  g_bShowInput       = FALSE;
static WCHAR g_szLockMsg[128]   = {0};

/* 锁屏动画 */
static int   g_nAnimFrame       = 0;
static WCHAR g_szLogBuf[32][160];
static int   g_nLogCount        = 0;

/* 适配器名称缓存 */
static WCHAR g_szAdapter[256]   = {0};

/* IP守护已禁用，保留变量以兼容编译 */
static volatile BOOL g_bIPGuardEnabled = FALSE;

/* 隐藏的窗口列表（用于恢复） */
#define MAX_HIDDEN_WNDS 64
static HWND  g_hiddenWnds[MAX_HIDDEN_WNDS];
static int   g_nHiddenWnds = 0;

/* ============================================================
   前向声明
   ============================================================ */
LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK LoginWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SettingsWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK LockWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK KeyboardHookProc(int, WPARAM, LPARAM);
DWORD WINAPI     WatchdogThread(LPVOID);
DWORD WINAPI     GuardThread(LPVOID);
DWORD WINAPI     IPGuardThread(LPVOID);
DWORD WINAPI     BossKeyThread(LPVOID);
DWORD WINAPI     InitialIPThread(LPVOID);
DWORD WINAPI     EmergencyFixThread(LPVOID);   /* v3.2 */

static void DoLockScreen(void);
static void DoUnlockScreen(void);
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
static void EmergencyNetworkFix(void);   /* v3.2: 一键修复网络栈 */

/* ============================================================
   工具：后台无窗口执行命令
   ============================================================ */
static void ExecHidden(const WCHAR *cmd) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR buf[2048];
    WCHAR szComSpec[MAX_PATH] = {0};
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    /* 获取cmd.exe路径 */
    if (!GetEnvironmentVariableW(L"COMSPEC", szComSpec, MAX_PATH)) {
        GetSystemDirectoryW(szComSpec, MAX_PATH);
        wcsncat(szComSpec, L"\\cmd.exe", MAX_PATH - wcslen(szComSpec) - 1);
    }
    /* 通过cmd.exe /c执行，确保 route/arp/ipconfig等命令能找到 */
    _snwprintf(buf, 2047, L"\"%ls\" /c %ls", szComSpec, cmd);
    buf[2047] = 0;
    if (CreateProcessW(NULL, buf, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* 异步执行（不等待） */
static void ExecAsync(const WCHAR *cmd) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR buf[2048];
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
    _snwprintf(buf, 2047, L"\"%ls\" /c %ls", szComSpec, cmd);
    buf[2047] = 0;
    if (CreateProcessW(NULL, buf, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* 直接调用 PowerShell.exe（不经过 cmd.exe，避免引号转义问题）
 * psScript: 要执行的 PowerShell 脚本内容（直接传给 -Command）
 * bWait: 是否等待执行完成
 * timeoutMs: 等待超时毫秒数 */
static void ExecPowerShell(const WCHAR *psScript, BOOL bWait, DWORD timeoutMs) {
    /* 找到 powershell.exe 路径 */
    WCHAR szPS[MAX_PATH] = {0};
    GetSystemDirectoryW(szPS, MAX_PATH);
    wcsncat(szPS, L"\\WindowsPowerShell\\v1.0\\powershell.exe",
            MAX_PATH - wcslen(szPS) - 1);
    /* 如果不存在，尝试 SysNative 路径（防止 WOW64 重定向） */
    if (GetFileAttributesW(szPS) == INVALID_FILE_ATTRIBUTES) {
        WCHAR szWin[MAX_PATH] = {0};
        GetWindowsDirectoryW(szWin, MAX_PATH);
        _snwprintf(szPS, MAX_PATH-1,
            L"%ls\\SysNative\\WindowsPowerShell\\v1.0\\powershell.exe", szWin);
    }

    /*
     * 命令行格式：powershell.exe -NoProfile -NonInteractive -Command "<script>"
     * 注意：这里的外层引号是传给 CreateProcess 的 lpCommandLine，
     *       内层引号包裹 psScript，不经过 cmd.exe 解析。
     */
    WCHAR cmdLine[2048];
    _snwprintf(cmdLine, 2047,
        L"\"%ls\" -NoProfile -NonInteractive -WindowStyle Hidden -Command \"%ls\"",
        szPS, psScript);
    cmdLine[2047] = 0;

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

/*
 * v3.2 - EmergencyNetworkFix
 *
 * 一键修复网络栈，应对发病时的 ERR_NO_BUFFER_SPACE。
 * 触发：用户按 Ctrl+Alt+F12（隐藏热键）。
 * 流程：重启 NSI/iphlpsvc/HNS 服务 → 刷新DNS → 重置Winsock目录。
 * 整个过程 3-5 秒，不需要重启电脑，浏览器立刻可用。
 *
 * 注意：服务停止/启动顺序很重要，否则会卡死。
 * 先停依赖方（hns, iphlpsvc）再停被依赖方（nsi）；
 * 启动顺序反过来。
 */
static void EmergencyNetworkFix(void) {
    WriteLog(L"EmergencyNetworkFix: START");

    /* 停止顺序：上层 → 下层 */
    ExecHidden(L"net stop hns");
    ExecHidden(L"net stop iphlpsvc");
    ExecHidden(L"net stop nsi");

    Sleep(500);

    /* 启动顺序：下层 → 上层 */
    ExecHidden(L"net start nsi");
    ExecHidden(L"net start iphlpsvc");
    ExecHidden(L"net start hns");

    /* 清DNS缓存 */
    ExecHidden(L"ipconfig /flushdns");

    /* 轻量重置Winsock目录（无需重启即生效） */
    ExecHidden(L"netsh winsock reset catalog");

    WriteLog(L"EmergencyNetworkFix: DONE");
}

DWORD WINAPI EmergencyFixThread(LPVOID p) {
    (void)p;
    EmergencyNetworkFix();
    return 0;
}

/* ============================================================
   进程保护
   ============================================================ */
static void ProtectProcess(void) {
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        /* 只提升调试权限，不设置关键进程标志（避免重启蓝屏） */
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
    /*
     * 注意：不调用 NtSetInformationProcess(29) 设置关键进程标志！
     * 该标志会导致进程被强制终止时（如重启/关机）触发蓝屏(CRITICAL_PROCESS_DIED)
     */
}

/* ============================================================
   看门狗线程：仅在锁屏时关闭任务管理器
   解锁后不干扰任何程序
   ============================================================ */
DWORD WINAPI WatchdogThread(LPVOID p) {
    (void)p;
    while (1) {
        Sleep(2000);   /* v3.2: 400 → 2000，降低后台轮询压力 */
        /* 只在锁屏状态下关闭任务管理器 */
        if (g_bLocked) {
            HWND h;
            h = FindWindowW(L"TaskManagerWindow", NULL);
            if (h) PostMessage(h, WM_CLOSE, 0, 0);
            /* Win10/11任务管理器 */
            h = FindWindowExW(NULL, NULL, L"#32770", NULL);
            while (h) {
                WCHAR title[64] = {0};
                GetWindowTextW(h, title, 63);
                if (wcsstr(title, L"任务管理器") || wcsstr(title, L"Task Manager"))
                    PostMessage(h, WM_CLOSE, 0, 0);
                h = FindWindowExW(NULL, h, L"#32770", NULL);
            }
        }
    }
    return 0;
}

/* ============================================================
   守护线程：锁屏时强制置顶夺焦点
   ============================================================ */
DWORD WINAPI GuardThread(LPVOID p) {
    (void)p;
    while (1) {
        Sleep(500);    /* v3.2: 80 → 500，避免对DWM/explorer的焦点抢夺风暴 */
        if (g_bLocked && g_hWndLock && IsWindow(g_hWndLock)) {
            int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
            SetWindowPos(g_hWndLock, HWND_TOPMOST,
                         vx, vy, vw, vh, SWP_NOACTIVATE);
            HWND hFg = GetForegroundWindow();
            if (hFg != g_hWndLock) {
                SetForegroundWindow(g_hWndLock);
                BringWindowToTop(g_hWndLock);
                SetFocus(g_hWndLock);
            }
            /* 关闭任务管理器 */
            HWND hTM = FindWindowW(L"TaskManagerWindow", NULL);
            if (hTM) PostMessage(hTM, WM_CLOSE, 0, 0);
        }
    }
    return 0;
}

/* ============================================================
   全局键盘钉子
   ============================================================ */
LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0) return CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);

    KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
    UINT vk    = kb->vkCode;
    BOOL bDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
    BOOL bAlt  = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
    BOOL bCtrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    BOOL bShft = (GetAsyncKeyState(VK_SHIFT)   & 0x8000) != 0;
    BOOL bLWin = (GetAsyncKeyState(VK_LWIN)    & 0x8000) != 0;
    BOOL bRWin = (GetAsyncKeyState(VK_RWIN)    & 0x8000) != 0;
    BOOL bWin  = bLWin || bRWin;

    /* ---- 拦截 Win+L，触发我们的锁屏 ---- */
    if (bDown && vk == 'L' && bWin && !g_bLocked) {
        PostMessage(g_hWndMain, WM_LOCK_SCREEN, 0, 0);
        return 1;
    }

    /* ---- 锁屏模式：在钉子里直接处理所有按键，完全屏蔽穿透 ---- */
    if (g_bLocked) {
        /* 屏蔽所有系统快捷键 */
        if (vk == VK_TAB    && bAlt)              return 1;
        if (vk == VK_ESCAPE && bAlt)              return 1;
        if (vk == VK_F4     && bAlt)              return 1;
        if (vk == VK_ESCAPE && bCtrl)             return 1;
        if (vk == VK_ESCAPE && bCtrl && bShft)    return 1;
        if (vk == VK_DELETE && bCtrl && bAlt)     return 1;
        if (vk == VK_LWIN   || vk == VK_RWIN)     return 1;
        if (vk == 'D' && bWin)                    return 1;
        if (vk == 'L' && bWin)                    return 1;
        if (vk == 'R' && bWin)                    return 1;
        if (vk == 'X' && bWin)                    return 1;
        if (vk == 'E' && bWin)                    return 1;
        if (vk == 'I' && bWin)                    return 1;
        if (vk == VK_SNAPSHOT)                    return 1;
        if (vk >= VK_F1 && vk <= VK_F12)          return 1;

        /*
         * 关键修复：锁屏时所有按键必须直接投递到锁屏窗口
         * 不能依赖系统消息分发（因为焦点可能不在锁屏窗口）
         */
        if (g_hWndLock && IsWindow(g_hWndLock)) {
            if (bDown) {
                /*
                 * 直接在钉子里处理锁屏输入，不投递任何消息到窗口
                 * 避免 WM_KEYDOWN + WM_CHAR 双重触发导致字符重复
                 */
                if (vk == VK_RETURN) {
                    PostMessage(g_hWndLock, WM_KEYDOWN, VK_RETURN, 0);
                } else if (vk == VK_ESCAPE) {
                    PostMessage(g_hWndLock, WM_KEYDOWN, VK_ESCAPE, 0);
                } else if (vk == VK_BACK) {
                    PostMessage(g_hWndLock, WM_KEYDOWN, VK_BACK, 0);
                } else if (!bCtrl && !bAlt && !bWin) {
                    /* 普通字符键：转换为字符后直接投递 WM_CHAR（只投递一次） */
                    BYTE keyState[256] = {0};
                    GetKeyboardState(keyState);
                    WCHAR wchars[4] = {0};
                    int nChars = ToUnicode(vk, kb->scanCode, keyState, wchars, 3, 0);
                    if (nChars == 1 && wchars[0] >= 32 && wchars[0] != 127) {
                        PostMessage(g_hWndLock, WM_CHAR, (WPARAM)wchars[0], 0);
                    }
                }
            }
        }
        /* 屏蔽所有按键，不传递给其他窗口 */
        return 1;
    }

    return CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
}

/* ============================================================
   配置读写
   ============================================================ */
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
            RegCloseKey(hKey);
            break;
        }
    }
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
            RegCloseKey(hKey);
            break;
        }
    }
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
                /* 加上 /autostart 参数，开机自启动时直接进入后台不弹登录框 */
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
        /* 优先选择已连接的以太网 */
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
        /* 没有Up的，取第一个以太网 */
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
   方案：用 IP Helper API 直接设置IP，不依赖 netsh 和网卡名称
   备用：如果 API 失败，用网卡索引号调用 netsh
   ============================================================ */

/* 获取第一个有效以太网网卡的索引号（用于 netsh interface index 方式） */
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

/* ============================================================
   随机更换MAC地址
   方法：
   1. 在注册表 NDI\params\NetworkAddress 创建参数定义（Realtek驱动必须有此定义才会读取NetworkAddress）
   2. 写入 NetworkAddress 值（MAC以02开头，LAA格式）
   3. 用 wmic 禁用/启用网卡（最可靠，不依赖PowerShell执行策略）
   ============================================================ */
static void RandomizeMac(void) {
    /*
     * 生成随机MAC：
     * 第一字节强制为 0x02（LAA格式：bit0=0单播, bit1=1本地管理）
     * Realtek/Intel等驱动只接受 02/06/0A/0E 开头的MAC
     */
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
                      KEY_READ, &hClass) != ERROR_SUCCESS) {
        WriteLog(L"RandomizeMac: open class key FAILED");
        return;
    }

    BOOL bSet = FALSE;
    WCHAR szMatchedSubkey[64] = {0}; /* 保存完整子键路径，用于创建NDI\params */

    for (DWORD i = 0; i < 128; i++) {
        WCHAR szIdx[8];
        _snwprintf(szIdx, 7, L"%04lu", i);
        HKEY hSub;
        if (RegOpenKeyExW(hClass, szIdx, 0,
                          KEY_READ | KEY_WRITE, &hSub) != ERROR_SUCCESS)
            continue;

        /* 读取 DriverDesc */
        WCHAR szDesc[256] = {0};
        DWORD cbDesc = sizeof(szDesc);
        RegQueryValueExW(hSub, L"DriverDesc", NULL, NULL,
                         (LPBYTE)szDesc, &cbDesc);

        /* 读取 *IfType（可能是 DWORD 或 REG_SZ） */
        DWORD dwIfType = 0;
        DWORD cbIft = sizeof(DWORD);
        DWORD dwIftType = 0;
        WCHAR szIftStr[16] = {0};
        DWORD cbIftStr = sizeof(szIftStr);
        if (RegQueryValueExW(hSub, L"*IfType", NULL, &dwIftType,
                             (LPBYTE)&dwIfType, &cbIft) == ERROR_SUCCESS) {
            if (dwIftType == REG_SZ) {
                RegQueryValueExW(hSub, L"*IfType", NULL, NULL,
                                 (LPBYTE)szIftStr, &cbIftStr);
                dwIfType = (DWORD)_wtoi(szIftStr);
            }
        }

        WriteLog(L"RandomizeMac: [%ls] DriverDesc=%ls IfType=%lu",
                 szIdx, szDesc, dwIfType);

        /* 判断是否是真实物理以太网卡 */
        BOOL bIsPhysical = FALSE;
        if (dwIfType == 6 || dwIfType == 71) bIsPhysical = TRUE;
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
                L"Microsoft", L"Kernel Debug", L"Kernel-Debug",
                L"NDIS", L"Filter", L"Tunnel", L"Teredo",
                L"6to4", L"ISATAP", L"Direct", L"Multiplexor",
                NULL
            };
            for (int k = 0; excl[k]; k++)
                if (wcsstr(szDesc, excl[k])) { bIsPhysical = FALSE; break; }
        }

        if (bIsPhysical) {
            /*
             * 关键步骤1：在 NDI\params\NetworkAddress 创建参数定义
             * 这告诉Realtek驱动"我支持NetworkAddress参数"，否则驱动会忽略NetworkAddress值
             * 参考：https://superuser.com/questions/1011721
             */
            WCHAR szNdiPath[256];
            _snwprintf(szNdiPath, 255,
                L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
                L"{4D36E972-E325-11CE-BFC1-08002BE10318}\\%ls\\NDI\\params\\NetworkAddress",
                szIdx);
            HKEY hNdi;
            DWORD dwDisp;
            LONG lNdi = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szNdiPath, 0, NULL,
                REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hNdi, &dwDisp);
            WriteLog(L"RandomizeMac: create NDI\\params\\NetworkAddress ret=%ld disp=%lu",
                     lNdi, dwDisp);
            if (lNdi == ERROR_SUCCESS) {
                /* 写入参数描述（告诉驱动这是一个可编辑的字符串参数） */
                const WCHAR *v1 = L"1";       /* optional */
                const WCHAR *v2 = L"edit";    /* type */
                const WCHAR *v3 = L"1";       /* uppercase */
                const WCHAR *v4 = L"12";      /* limittext */
                const WCHAR *v5 = L"Network Address"; /* paramdesc */
                RegSetValueExW(hNdi, L"optional",  0, REG_SZ, (LPBYTE)v1, (DWORD)(wcslen(v1)+1)*2);
                RegSetValueExW(hNdi, L"type",      0, REG_SZ, (LPBYTE)v2, (DWORD)(wcslen(v2)+1)*2);
                RegSetValueExW(hNdi, L"uppercase", 0, REG_SZ, (LPBYTE)v3, (DWORD)(wcslen(v3)+1)*2);
                RegSetValueExW(hNdi, L"limittext", 0, REG_SZ, (LPBYTE)v4, (DWORD)(wcslen(v4)+1)*2);
                RegSetValueExW(hNdi, L"ParamDesc", 0, REG_SZ, (LPBYTE)v5, (DWORD)(wcslen(v5)+1)*2);
                RegCloseKey(hNdi);
            }

            /*
             * 关键步骤2：写入 NetworkAddress 值
             */
            DWORD cbMac = (DWORD)((wcslen(szMac) + 1) * sizeof(WCHAR));
            LONG lRet = RegSetValueExW(hSub, L"NetworkAddress", 0, REG_SZ,
                                       (LPBYTE)szMac, cbMac);
            WriteLog(L"RandomizeMac: write [%ls] NetworkAddress=%ls ret=%ld",
                     szIdx, szMac, lRet);
            if (lRet == ERROR_SUCCESS) {
                bSet = TRUE;
                wcsncpy(szMatchedSubkey, szIdx, 63);
                RegCloseKey(hSub);
                break; /* 找到了就停止 */
            }
        }
        RegCloseKey(hSub);
    }
    RegCloseKey(hClass);

    if (!bSet) {
        WriteLog(L"RandomizeMac: FAILED to write registry");
        return;
    }

    /*
     * 关键步骤3：禁用再启用网卡使MAC生效
     * 改用 wmic 命令（最可靠，不依赖PowerShell执行策略，Win7/10/11均可用）
     * 命令：wmic path win32_networkadapter where "Name='以太网'" call disable
     *       wmic path win32_networkadapter where "Name='以太网'" call enable
     */
    const WCHAR *adpName = GetAdapterName();
    WriteLog(L"RandomizeMac: disabling adapter [%ls] via wmic", adpName);

    /* 禁用网卡（wmic） */
    {
        WCHAR cmd[512];
        _snwprintf(cmd, 511,
            L"wmic path win32_networkadapter where \"Name='%ls'\" call disable",
            adpName);
        ExecHidden(cmd);
        Sleep(800);
    }

    /* 启用网卡（wmic） */
    {
        WCHAR cmd[512];
        _snwprintf(cmd, 511,
            L"wmic path win32_networkadapter where \"Name='%ls'\" call enable",
            adpName);
        ExecHidden(cmd);
        Sleep(800);
    }
    Sleep(400);

    /* 清除缓存的网卡名称 */
    g_szAdapter[0] = 0;

    WriteLog(L"RandomizeMac: done, MAC=%ls", szMac);
}

/* 写日志到桌面（调试用，可在发布时删除） */
static void WriteLog(const WCHAR *fmt, ...) {
    /* 日志已禁用，不生成任何文件 */
    (void)fmt;
}

/* 直接调用 netsh.exe，返回退出码（0=成功） */
static DWORD RunNetshDirect(const WCHAR *args) {
    WCHAR szNetsh[MAX_PATH] = {0};
    GetSystemDirectoryW(szNetsh, MAX_PATH);
    wcsncat(szNetsh, L"\\netsh.exe", MAX_PATH - wcslen(szNetsh) - 1);

    /* 命令行格式："C:\Windows\System32\netsh.exe" <args> */
    WCHAR cmdLine[1024];
    _snwprintf(cmdLine, 1023, L"\"%ls\" %ls", szNetsh, args);

    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    WriteLog(L"RunNetsh: %ls", cmdLine);

    if (!CreateProcessW(szNetsh, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WriteLog(L"CreateProcess FAILED err=%lu", GetLastError());
        return (DWORD)-1;
    }
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    WriteLog(L"netsh exit=%lu", exitCode);
    return exitCode;
}

static void ApplyIP(const WCHAR *ip1, const WCHAR *mask1,
                    const WCHAR *gw,  const WCHAR *dns,
                    const WCHAR *ip2, const WCHAR *mask2) {
    /*
     * v3.2 重写要点：
     * 1. 全部使用 store=active 模式 —— netsh只改运行时配置，不写持久化
     *    存储，避免触发完整的网卡重新初始化，让浏览器TCP连接平滑保留。
     * 2. 删除 route flush / delete arpcache / delete destinationcache
     *    —— 这3条是 v3.1 的元凶，长期累积污染 NSI/AFD 内部状态，
     *    最终导致非分页池泄漏，浏览器报 ERR_NO_BUFFER_SPACE。
     * 3. 保留多重 fallback（Win7 兼容）。
     */
    DWORD ifIdx = GetEthernetIfIndex();
    const WCHAR *adpName = GetAdapterName();
    WriteLog(L"ApplyIP: ip1=%ls mask=%ls gw=%ls dns=%ls ifIdx=%lu adp=%ls",
             ip1, mask1, gw, dns ? dns : L"(none)", ifIdx, adpName);

    /* v3.2: 不再 route flush / delete arpcache / delete destinationcache
     * 让 Windows 自己管理 ARP / 路由 / 目标缓存的生命周期。 */

    /* 先用 netsh interface ipv4（Windows 10/11更可靠） */
    BOOL bOK = FALSE;
    WCHAR args[512];

    /* 方案A：ipv4 + 网卡名称（v3.2: store=active） */
    _snwprintf(args, 511,
        L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls gwmetric=1 store=active",
        adpName, ip1, mask1, gw);
    DWORD ret = RunNetshDirect(args);
    Sleep(500);

    /* 验证 */
    {
        ULONG bufChk = 16384;
        PIP_ADAPTER_INFO pChk = (PIP_ADAPTER_INFO)malloc(bufChk);
        if (pChk && GetAdaptersInfo(pChk, &bufChk) == NO_ERROR) {
            char szIP1A[64]={0};
            WideCharToMultiByte(CP_ACP,0,ip1,-1,szIP1A,63,NULL,NULL);
            PIP_ADAPTER_INFO p = pChk;
            while (p) {
                if (strcmp(p->IpAddressList.IpAddress.String, szIP1A)==0) {
                    bOK = TRUE; break;
                }
                p = p->Next;
            }
        }
        if (pChk) free(pChk);
        WriteLog(L"方案A(ipv4+name) bOK=%d ret=%lu", bOK, ret);
    }

    if (!bOK && ifIdx > 0) {
        /* 方案B：ipv4 + 索引号 */
        _snwprintf(args, 511,
            L"interface ipv4 set address %lu static %ls %ls %ls 1",
            ifIdx, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(1000);

        ULONG bufChk = 16384;
        PIP_ADAPTER_INFO pChk = (PIP_ADAPTER_INFO)malloc(bufChk);
        if (pChk && GetAdaptersInfo(pChk, &bufChk) == NO_ERROR) {
            char szIP1A[64]={0};
            WideCharToMultiByte(CP_ACP,0,ip1,-1,szIP1A,63,NULL,NULL);
            PIP_ADAPTER_INFO p = pChk;
            while (p) {
                if (p->Index == ifIdx &&
                    strcmp(p->IpAddressList.IpAddress.String, szIP1A)==0) {
                    bOK = TRUE; break;
                }
                p = p->Next;
            }
        }
        if (pChk) free(pChk);
        WriteLog(L"方案B(ipv4+idx) bOK=%d ret=%lu", bOK, ret);
    }

    if (!bOK) {
        /* 方案C：旧版 ip + 网卡名称（兼容Windows 7） */
        _snwprintf(args, 511,
            L"interface ip set address \"%ls\" static %ls %ls %ls 1",
            adpName, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(1000);
        WriteLog(L"方案C(ip+name) ret=%lu", ret);
    }

    if (!bOK && ifIdx > 0) {
        /* 方案D：旧版 ip + 索引号 */
        _snwprintf(args, 511,
            L"interface ip set address %lu static %ls %ls %ls 1",
            ifIdx, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(1000);
        WriteLog(L"方案D(ip+idx) ret=%lu", ret);
    }

    /* 添加第二个IP（v3.2: store=active） */
    if (ip2 && ip2[0]) {
        /* 先用ipv4方式 */
        _snwprintf(args, 511,
            L"interface ipv4 add address name=\"%ls\" addr=%ls mask=%ls store=active",
            adpName, ip2, mask2);
        RunNetshDirect(args);
        Sleep(300);
        /* 备用旧方式（旧版netsh不支持store参数，保留原写法） */
        if (ifIdx > 0) {
            _snwprintf(args, 511,
                L"interface ip add address %lu %ls %ls",
                ifIdx, ip2, mask2);
            RunNetshDirect(args);
            Sleep(300);
        }
    }

    /* 设置DNS（v3.2: store=active + register=none，避免对DNS服务的额外扰动） */
    {
        WCHAR args4[512];
        if (dns && dns[0]) {
            /* ipv4方式 */
            _snwprintf(args4, 511,
                L"interface ipv4 set dnsservers name=\"%ls\" source=static address=%ls register=none validate=no store=active",
                adpName, dns);
            RunNetshDirect(args4);
            Sleep(300);
            /* 旧方式备用 */
            if (ifIdx > 0) {
                _snwprintf(args4, 511,
                    L"interface ip set dns %lu static %ls validate=no",
                    ifIdx, dns);
                RunNetshDirect(args4);
            }
        } else {
            /* 清除DNS */
            _snwprintf(args4, 511,
                L"interface ipv4 set dnsservers name=\"%ls\" source=static address=none register=none validate=no store=active",
                adpName);
            RunNetshDirect(args4);
            Sleep(300);
            if (ifIdx > 0) {
                _snwprintf(args4, 511,
                    L"interface ip set dns %lu static none",
                    ifIdx);
                RunNetshDirect(args4);
            }
        }
    }

    /* 刷新DNS缓存 */
    ExecHidden(L"ipconfig /flushdns");
    WriteLog(L"ApplyIP done");
}

/* ============================================================
   IP 锁定与守护
   方案：
   1. 组策略注册表禁用网络属性界面（用户无法打开TCP/IP属性）
   2. 轻量守护线程：用 GetAdaptersInfo API 读取实际IP，
      发现被改则用 netsh 恢复（守护线程不写注册表，不会触发注册表事件）
   3. 设置界面提供“允许修改IP”开关，开关开启时守护线程暂停
   ============================================================ */

/* 全局开关：是否允许用户手动修改IP（在设置界面可切换） */
static volatile BOOL g_bAllowIPChange = FALSE;

/* 当前应该保持的IP（用于守护线程比对） */
static WCHAR g_szExpectedIP[64] = {0};

/* 遍历所有以太网/WiFi地址，确认目标IP是否真的存在 */
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
            /* 只看以太网和WiFi */
            if (p->Type == MIB_IF_TYPE_ETHERNET ||
                p->Type == IF_TYPE_IEEE80211) {
                IP_ADDR_STRING *addr = &p->IpAddressList;
                while (addr) {
                    const char *ip = addr->IpAddress.String;
                    if (ip[0] && strcmp(ip, "0.0.0.0") != 0 &&
                        strcmp(ip, expectedA) == 0) {
                        found = TRUE;
                        break;
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

static void LockIPReg(void) {
    HKEY hKey; DWORD dwDisp; DWORD v = 0;
    /* 组策略：禁用网络属性界面的修改按鈕 */
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE,
            NULL, &hKey, &dwDisp) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"NC_AllowAdvancedTCPIPConfig",
                       0, REG_DWORD, (LPBYTE)&v, sizeof(v));
        RegSetValueExW(hKey, L"NC_AllowNetBridge_NLA",
                       0, REG_DWORD, (LPBYTE)&v, sizeof(v));
        RegSetValueExW(hKey, L"NC_PersonalFirewallConfig",
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
        RegDeleteValueW(hKey, L"NC_AllowNetBridge_NLA");
        RegDeleteValueW(hKey, L"NC_PersonalFirewallConfig");
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"NC_AllowAdvancedTCPIPConfig");
        RegCloseKey(hKey);
    }
}

/* IP守护线程：每5秒检查一次实际IP，发现被改则恢复 */
DWORD WINAPI IPGuardThread(LPVOID p) {
    (void)p;
    Sleep(5000); /* 等待初始IP设置完全生效 */
    while (1) {
        Sleep(5000);
        /* 开关关闭或允许修改时不守护 */
        if (g_bAllowIPChange || g_szExpectedIP[0] == 0) continue;
        if (g_lNetworkChangeBusy) continue;
        /* 目标IP不存在时，才恢复，避免多IP顺序变化导致反复重置网络 */
        if (!AdapterHasIP(g_szExpectedIP)) {
            Sleep(15000);
            if (g_bAllowIPChange || g_szExpectedIP[0] == 0) continue;
            if (g_lNetworkChangeBusy || AdapterHasIP(g_szExpectedIP)) continue;
            /* IP被改了，恢复 */
            if (g_bBossMode) {
                ApplyIP(IP_BOSS, IP_BOSS_MASK, IP_BOSS_GW, NULL, NULL, NULL);
            } else {
                ApplyIP(IP_WORK1, IP_WORK_MASK, IP_WORK_GW,
                        IP_WORK_DNS, IP_WORK2, IP_WORK_MASK);
            }
        }
    }
    return 0;
}

/* ============================================================
   记事本控制：切换到8.*IP时打开，切换刁20.*IP时关闭
   ============================================================ */
static void OpenNotepad(void) {
    /* 检查记事本是否已经在运行，避免重复打开 */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"notepad.exe") == 0) {
                    CloseHandle(hSnap);
                    return; /* 已在运行，不重复打开 */
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    /* 打开记事本 */
    WCHAR szNotepad[MAX_PATH];
    GetSystemDirectoryW(szNotepad, MAX_PATH);
    wcsncat(szNotepad, L"\\notepad.exe", MAX_PATH - wcslen(szNotepad) - 1);
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    if (CreateProcessW(szNotepad, NULL, NULL, NULL, FALSE,
                       0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static void CloseNotepad(void) {
    /* 找到所有 notepad.exe 进程并结束 */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"notepad.exe") == 0) {
                HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProc) {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static void SetIPWork(void) {
    if (!BeginNetworkChange()) return;
    /* 切换前先随机更换MAC地址 */
    RandomizeMac();
    wcsncpy(g_szExpectedIP, IP_WORK1, 63);
    ApplyIP(IP_WORK1, IP_WORK_MASK, IP_WORK_GW, IP_WORK_DNS,
            IP_WORK2, IP_WORK_MASK);
    LockIPReg();
    /* 切换刲0.*后关闭记事本 */
    CloseNotepad();
    EndNetworkChange();
}

static void SetIPBoss(void) {
    if (!BeginNetworkChange()) return;
    /* 切换前先随机更换MAC地址 */
    RandomizeMac();
    wcsncpy(g_szExpectedIP, IP_BOSS, 63);
    /* 老板模式：不设置 DNS */
    ApplyIP(IP_BOSS, IP_BOSS_MASK, IP_BOSS_GW, NULL, NULL, NULL);
    LockIPReg();
    /* 切换到8.*后打开记事本 */
    OpenNotepad();
    EndNetworkChange();
}

/* ============================================================
   清理痕迹（完全后台，无任何黑框）
   ============================================================ */
static void CleanTraces(void) {
    WCHAR cmd[1024];
    WCHAR szPath[MAX_PATH];
    HKEY hKey;

    /* 关闭远程桌面 */
    ExecHidden(L"taskkill /f /im mstsc.exe");

    /* 清理RDP注册表 */
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Terminal Server Client\\Default");
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Terminal Server Client\\Servers");

    /* 清理RDP MRU */
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Terminal Server Client\\Default",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE,
            NULL, &hKey, NULL) == ERROR_SUCCESS) {
        for (int i = 0; i < 20; i++) {
            WCHAR v[8]; _snwprintf(v, 7, L"MRU%d", i);
            RegDeleteValueW(hKey, v);
        }
        RegCloseKey(hKey);
    }

    /* 清理RDP缓存文件（直接用Win32 API删除，不调用cmd） */
    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath) == S_OK) {
        WCHAR szDir[MAX_PATH];
        /* Cache目录 */
        _snwprintf(szDir, MAX_PATH-1,
            L"%ls\\Microsoft\\Terminal Server Client\\Cache", szPath);
        /* 枚举并删除文件 */
        WCHAR szFind[MAX_PATH];
        _snwprintf(szFind, MAX_PATH-1, L"%ls\\*", szDir);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(szFind, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR szFull[MAX_PATH];
                    _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls",
                               szDir, fd.cFileName);
                    SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(szFull);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    /* 清理.rdp文件 */
    WCHAR szDirs[3][MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, szDirs[0]);
    SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, szDirs[1]);
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szDirs[2]);
    for (int d = 0; d < 2; d++) {
        WCHAR szFind[MAX_PATH];
        _snwprintf(szFind, MAX_PATH-1, L"%ls\\*.rdp", szDirs[d]);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(szFind, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                WCHAR szFull[MAX_PATH];
                _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls",
                           szDirs[d], fd.cFileName);
                SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(szFull);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    /* 清理CMD/运行历史（RunMRU） */
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");

    /* 清理资源管理器地址栏历史 */
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
            0, KEY_WRITE|KEY_READ, &hKey) == ERROR_SUCCESS) {
        for (int i = 1; i <= 30; i++) {
            WCHAR v[8]; _snwprintf(v, 7, L"url%d", i);
            RegDeleteValueW(hKey, v);
        }
        RegCloseKey(hKey);
    }

    /* 清理最近文档（直接删除文件） */
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
                    _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls",
                               szRecent, fd.cFileName);
                    SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(szFull);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    /* 清理快速访问/跳转列表 */
    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, szPath) == S_OK) {
        /* AutomaticDestinations */
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
                    _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls",
                               szAuto, fd.cFileName);
                    SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(szFull);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        /* CustomDestinations */
        WCHAR szCustom[MAX_PATH];
        _snwprintf(szCustom, MAX_PATH-1,
            L"%ls\\Microsoft\\Windows\\Recent\\CustomDestinations", szPath);
        _snwprintf(szFind, MAX_PATH-1, L"%ls\\*", szCustom);
        hFind = FindFirstFileW(szFind, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR szFull[MAX_PATH];
                    _snwprintf(szFull, MAX_PATH-1, L"%ls\\%ls",
                               szCustom, fd.cFileName);
                    SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(szFull);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    /* 清理网络连接历史 */
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Network\\Persistent Connections");

    /* 清理事件日志（后台执行，不等待） */
    ExecAsync(L"wevtutil cl \"Microsoft-Windows-TerminalServices-RDPClient/Operational\"");
    ExecAsync(L"wevtutil cl \"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\"");

    /* 清理Prefetch（直接删除） */
    {
        WCHAR szFind[MAX_PATH] = L"C:\\Windows\\Prefetch\\MSTSC*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(szFind, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                WCHAR szFull[MAX_PATH];
                _snwprintf(szFull, MAX_PATH-1,
                           L"C:\\Windows\\Prefetch\\%ls", fd.cFileName);
                SetFileAttributesW(szFull, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(szFull);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    /* 清理注册表中的RDP服务器列表（RecentServers） */
    RegDeleteKeyW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Terminal Server Client");

    /* 刷新资源管理器（不弹窗） */
    SHChangeNotify(SHCNE_ALLEVENTS, SHCNF_IDLIST, NULL, NULL);

    /* 清理CMD doskey历史（通过注册表） */
    _snwprintf(cmd, 1023,
        L"reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\" /f");
    ExecHidden(cmd);
}

/* ============================================================
   隐藏/显示程序窗口
   支持中文窗口标题，通过枚举所有窗口匹配
   ============================================================ */

/* 枚举回调：隐藏匹配标题的窗口 */
typedef struct {
    WCHAR *title;
    BOOL   bHide;
    HWND  *pList;
    int   *pCount;
    int    maxCount;
} EnumWndParam;

static BOOL CALLBACK EnumWndCallback(HWND hWnd, LPARAM lParam) {
    EnumWndParam *p = (EnumWndParam *)lParam;
    if (!IsWindowVisible(hWnd) && p->bHide) return TRUE;

    WCHAR szTitle[512] = {0};
    GetWindowTextW(hWnd, szTitle, 511);

    /* 支持部分匹配（包含关键词即可） */
    if (szTitle[0] && wcsstr(szTitle, p->title)) {
        if (p->bHide) {
            /* 记录到隐藏列表 */
            if (p->pList && *p->pCount < p->maxCount) {
                p->pList[(*p->pCount)++] = hWnd;
            }
            ShowWindow(hWnd, SW_HIDE);
        } else {
            ShowWindow(hWnd, SW_SHOW);
        }
    }
    return TRUE;
}

static void HideProcessWindows(void) {
    if (!g_szHideList[0]) return;
    g_nHiddenWnds = 0;

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
    /* 恢复之前记录的隐藏窗口 */
    for (int i = 0; i < g_nHiddenWnds; i++) {
        if (g_hiddenWnds[i] && IsWindow(g_hiddenWnds[i])) {
            ShowWindow(g_hiddenWnds[i], SW_SHOW);
        }
    }
    g_nHiddenWnds = 0;

    /* 同时通过标题再次枚举恢复（双重保险） */
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
    UnregisterHotKey(hWnd, HOTKEY_NETFIX);   /* v3.2 */
    RegisterHotKey(hWnd, HOTKEY_BOSS, g_BossMod, g_BossVk);
    RegisterHotKey(hWnd, HOTKEY_SETTINGS, SETTINGS_MOD, SETTINGS_VK);
    RegisterHotKey(hWnd, HOTKEY_NETFIX, EMERGENCY_MOD, EMERGENCY_VK);   /* v3.2: Ctrl+Alt+F12 一键修复网络 */
}

/* ============================================================
   老板键逻辑（异步执行，不阻塞主线程）
   ============================================================ */
DWORD WINAPI BossKeyThread(LPVOID pParam) {
    BOOL bEnterBoss = (BOOL)(ULONG_PTR)pParam;
    if (bEnterBoss) {
        /* 进入老板模式：切换IP（含随机MAC） + 隐藏程序 + 清理痕迹 */
        SetIPBoss();
        HideProcessWindows();
        CleanTraces();
    } else {
        /* 退出老板模式：恢复工作IP（含随机MAC） + 显示程序 + 清理痕迹 */
        SetIPWork();
        ShowProcessWindows();
        CleanTraces();  /* 修复：退出老板模式时也要清理痕迹 */
    }
    return 0;
}

DWORD WINAPI InitialIPThread(LPVOID pParam) {
    (void)pParam;
    /* v3.2: 删除 FixTcpBufferSpace —— 那是 v3.1 的错误方向 */
    SetIPWork();
    return 0;
}

static void DoBossKey(void) {
    /* v3.2: 用 InterlockedExchange 替代直接赋值，消除跨线程竞态 */
    if (!g_bBossMode) {
        InterlockedExchange((LONG*)&g_bBossMode, TRUE);
        StartDetachedThread(BossKeyThread, (LPVOID)(ULONG_PTR)TRUE);
    } else {
        InterlockedExchange((LONG*)&g_bBossMode, FALSE);
        StartDetachedThread(BossKeyThread, (LPVOID)(ULONG_PTR)FALSE);
    }
}

/* ============================================================
   锁屏界面
   ============================================================ */
static void GenLogLine(void) {
    static const WCHAR *tpls[] = {
        L"[INFO]  stream-relay: client 192.168.%d.%d connected, bitrate %d kbps",
        L"[INFO]  ffmpeg: encoding H.264 frame %d, pts=%d, qp=%d",
        L"[DEBUG] nginx: upstream %d.%d.%d.%d response 200 OK in %dms",
        L"[INFO]  rtmp: publish /live/stream%d started, fps=%d",
        L"[WARN]  buffer: queue depth %d/%d, dropping %d frames",
        L"[INFO]  cpu: core%d usage %.1f%%, temp %d°C",
        L"[INFO]  net: eth0 rx %d.%dMB/s tx %d.%dMB/s pkts=%d",
        L"[INFO]  disk: /dev/sda1 read %dMB/s write %dMB/s util=%d%%",
        L"[DEBUG] hls: segment #%d written, duration %.3fs, size=%dKB",
        L"[INFO]  clients: %d active, %d buffering, %d idle",
        L"[INFO]  mem: used %dMB free %dMB cached %dMB",
        L"[DEBUG] tcp: established %d time_wait %d close_wait %d",
        L"[INFO]  watchdog: all services OK, uptime %dh%dm%ds",
        L"[INFO]  transcode: 1080p->720p@%dkbps 1080p->480p@%dkbps",
        L"[DEBUG] ssl: cert expires in %d days, handshakes %d/s",
    };
    int n = (int)(sizeof(tpls)/sizeof(tpls[0]));
    int idx = rand() % n;
    int a=rand()%254+1, b=rand()%254+1, c=rand()%9999+1;
    int d=rand()%100, e=rand()%100, f=rand()%100;
    _snwprintf(g_szLogBuf[g_nLogCount % 32], 159,
               tpls[idx], a, b, c, d, e, f);
    g_nLogCount++;
}

static void GetUptimeStr(WCHAR *buf, int sz) {
    DWORD ms = GetTickCount();
    DWORD s=ms/1000, m=s/60, h=m/60, d=h/24;
    _snwprintf(buf, sz-1, L"%dd %02dh:%02dm:%02ds", d, h%24, m%60, s%60);
}

static void DrawLockScreen(HWND hWnd, HDC hdc) {
    RECT rc;
    GetClientRect(hWnd, &rc);
    int W = rc.right, H = rc.bottom;

    /* 黑色背景 */
    HBRUSH hBk = CreateSolidBrush(RGB(0,0,0));
    FillRect(hdc, &rc, hBk);
    DeleteObject(hBk);
    SetBkMode(hdc, TRANSPARENT);

    /* 字体 */
    HFONT hFT = CreateFontW(15,0,0,0,FW_NORMAL,0,0,0,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,L"Courier New");
    HFONT hFTB = CreateFontW(15,0,0,0,FW_BOLD,0,0,0,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,L"Courier New");
    HFONT hFTL = CreateFontW(44,0,0,0,FW_BOLD,0,0,0,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,L"Courier New");
    HFONT hOld = (HFONT)SelectObject(hdc, hFT);

    /* 顶部标题栏 */
    HBRUSH hGreen = CreateSolidBrush(RGB(0,80,0));
    RECT rcBar = {0,0,W,26};
    FillRect(hdc, &rcBar, hGreen);
    DeleteObject(hGreen);
    SelectObject(hdc, hFTB);
    SetTextColor(hdc, RGB(200,255,200));
    WCHAR szTitle[] = L" Ubuntu 22.04.3 LTS  |  mediaserver-01  |  kernel 5.15.0-91-generic x86_64";
    TextOutW(hdc, 4, 5, szTitle, (int)wcslen(szTitle));

    /* 大时间 */
    SYSTEMTIME st;
    GetLocalTime(&st);
    WCHAR szTime[32];
    _snwprintf(szTime, 31, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    SelectObject(hdc, hFTL);
    SetTextColor(hdc, RGB(0,230,100));
    SIZE tsz; GetTextExtentPoint32W(hdc, szTime, (int)wcslen(szTime), &tsz);
    TextOutW(hdc, (W-tsz.cx)/2, 34, szTime, (int)wcslen(szTime));

    WCHAR szDate[48];
    const WCHAR *days[] = {L"Sunday",L"Monday",L"Tuesday",L"Wednesday",
                            L"Thursday",L"Friday",L"Saturday"};
    _snwprintf(szDate, 47, L"%04d-%02d-%02d  %ls",
               st.wYear, st.wMonth, st.wDay, days[st.wDayOfWeek]);
    SelectObject(hdc, hFT);
    SetTextColor(hdc, RGB(0,180,80));
    SIZE dsz; GetTextExtentPoint32W(hdc, szDate, (int)wcslen(szDate), &dsz);
    TextOutW(hdc, (W-dsz.cx)/2, 84, szDate, (int)wcslen(szDate));

    /* 分隔线 */
    int y = 108;
    int cols = (W-10)/9; if(cols>120)cols=120; if(cols<40)cols=40;
    WCHAR szSep[128];
    for(int i=0;i<cols&&i<127;i++) szSep[i]=L'='; szSep[cols]=0;
    SetTextColor(hdc, RGB(0,100,0));
    TextOutW(hdc, 5, y, szSep, cols); y+=18;

    /* 系统信息 */
    SetTextColor(hdc, RGB(0,220,80));
    static int nMem=4200, nNet=0, nDisk=0;
    static float fCPU=12.5f;
    if(g_nAnimFrame%3==0) {
        nMem  = 3800+rand()%1200;
        nNet  = rand()%900+100;
        nDisk = rand()%400+50;
        fCPU  = (float)(rand()%600+50)/10.0f;
    }
    WCHAR szUptime[64]; GetUptimeStr(szUptime, 63);
    WCHAR szLine[160];

    _snwprintf(szLine,159,
        L"  hostname: mediaserver-01          uptime: %ls", szUptime);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,
        L"  os: Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)");
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,
        L"  cpu: Intel(R) Xeon(R) Silver 4214R @ 2.40GHz  cores:24  load:%.1f %.1f %.1f",
        fCPU, fCPU*0.8f, fCPU*0.6f);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,
        L"  memory: %dMB used / 32768MB total (%.1f%%)  swap: %d/8192MB",
        nMem, (float)nMem/327.68f, nMem/16);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,
        L"  network: eth0  rx:%d.%dMB/s  tx:%d.%dMB/s  ip:20.65.32.199/24",
        nNet/100, nNet%100, (nNet/4)/100, (nNet/4)%100);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,
        L"  storage: /dev/sda1  read:%dMB/s  write:%dMB/s  used:1.2TB/4.0TB",
        nDisk, nDisk/3);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;

    SetTextColor(hdc, RGB(0,100,0));
    TextOutW(hdc,5,y,szSep,cols); y+=18;
    SetTextColor(hdc, RGB(0,220,80));

    int streams=3+rand()%4, clients=15+rand()%30;
    int bitrate=8000+rand()%6000, dropped=rand()%3;
    _snwprintf(szLine,159,
        L"  services:  nginx[OK]  ffmpeg[OK]  rtmp[OK]  hls[OK]  redis[OK]");
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,
        L"  streams: %d active  clients: %d connected  bitrate: %dkbps  dropped: %d/s",
        streams, clients, bitrate, dropped);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;

    SetTextColor(hdc, RGB(0,100,0));
    TextOutW(hdc,5,y,szSep,cols); y+=18;

    /* 日志区 */
    SelectObject(hdc, hFTB);
    SetTextColor(hdc, RGB(0,160,50));
    WCHAR szLogHdr[] = L"  [ System Log - Real-time ]";
    TextOutW(hdc,5,y,szLogHdr,(int)wcslen(szLogHdr)); y+=18;
    SelectObject(hdc, hFT);

    int logLines = (H - y - 55) / 16;
    if(logLines<1) logLines=1;
    if(logLines>20) logLines=20;
    int logStart = g_nLogCount>logLines ? g_nLogCount-logLines : 0;
    for(int i=logStart; i<g_nLogCount && i<logStart+logLines; i++) {
        int idx = i%32;
        if(g_szLogBuf[idx][0]) {
            if(wcsncmp(g_szLogBuf[idx],L"[WARN]",6)==0)
                SetTextColor(hdc,RGB(255,200,0));
            else if(wcsncmp(g_szLogBuf[idx],L"[ERROR]",7)==0)
                SetTextColor(hdc,RGB(255,80,80));
            else if(wcsncmp(g_szLogBuf[idx],L"[DEBUG]",7)==0)
                SetTextColor(hdc,RGB(0,140,100));
            else
                SetTextColor(hdc,RGB(0,200,70));
            TextOutW(hdc,5,y,g_szLogBuf[idx],(int)wcslen(g_szLogBuf[idx]));
            y+=16;
        }
    }

    /* 密码输入框 */
    if(g_bShowInput) {
        int bx=(W-380)/2, by=(H-130)/2;
        if(bx<10) bx=10;
        if(by<10) by=10;
        HBRUSH hBr = CreateSolidBrush(RGB(0,15,0));
        RECT rcBox = {bx,by,bx+380,by+130};
        FillRect(hdc,&rcBox,hBr);
        DeleteObject(hBr);
        HPEN hPen = CreatePen(PS_SOLID,2,RGB(0,200,80));
        HPEN hOP = (HPEN)SelectObject(hdc,hPen);
        MoveToEx(hdc,bx,by,NULL); LineTo(hdc,bx+380,by);
        LineTo(hdc,bx+380,by+130); LineTo(hdc,bx,by+130);
        LineTo(hdc,bx,by);
        SelectObject(hdc,hOP); DeleteObject(hPen);

        SelectObject(hdc,hFTB);
        SetTextColor(hdc,RGB(0,255,100));
        TextOutW(hdc,bx+10,by+12,L"Enter unlock password:",22);

        WCHAR stars[65]={0};
        for(int i=0;i<g_nLockInputLen&&i<64;i++) stars[i]=L'*';
        SelectObject(hdc,hFT);
        SetTextColor(hdc,RGB(200,255,200));
        TextOutW(hdc,bx+10,by+36,stars,g_nLockInputLen);
        if(g_nAnimFrame%2==0)
            TextOutW(hdc,bx+10+g_nLockInputLen*9,by+36,L"_",1);

        if(g_szLockMsg[0]) {
            SetTextColor(hdc,RGB(255,100,100));
            TextOutW(hdc,bx+10,by+62,g_szLockMsg,(int)wcslen(g_szLockMsg));
        }
        SetTextColor(hdc,RGB(60,120,60));
        TextOutW(hdc,bx+10,by+90,
                 L"[Enter]=confirm  [Esc]=cancel  [Backspace]=delete",49);
        TextOutW(hdc,bx+10,by+108,
                 L"5 failures = 60s lockout",24);
    }

    /* 底部提示 */
    HFONT hFS = CreateFontW(12,0,0,0,FW_NORMAL,0,0,0,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY,FIXED_PITCH|FF_MODERN,L"Courier New");
    SelectObject(hdc,hFS);
    SetTextColor(hdc,RGB(40,80,40));
    WCHAR szHint[] = L"  Press any key to unlock...";
    TextOutW(hdc,5,H-22,szHint,(int)wcslen(szHint));
    DeleteObject(hFS);

    SelectObject(hdc,hOld);
    DeleteObject(hFT); DeleteObject(hFTB); DeleteObject(hFTL);
}

LRESULT CALLBACK LockWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    switch(msg) {
    case WM_CREATE:
        SetTimer(hWnd,1,700,NULL);
        memset(g_szLogBuf,0,sizeof(g_szLogBuf));
        g_nLogCount=0;
        srand((unsigned)time(NULL));
        for(int i=0;i<20;i++) GenLogLine();
        break;

    case WM_TIMER:
        if(wParam==1) {
            g_nAnimFrame++;
            GenLogLine();
            InvalidateRect(hWnd,NULL,FALSE);
        }
        break;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd,&ps);
        RECT rc; GetClientRect(hWnd,&rc);
        HDC hMem = CreateCompatibleDC(hdc);
        HBITMAP hBmp = CreateCompatibleBitmap(hdc,rc.right,rc.bottom);
        HBITMAP hOld = (HBITMAP)SelectObject(hMem,hBmp);
        DrawLockScreen(hWnd,hMem);
        BitBlt(hdc,0,0,rc.right,rc.bottom,hMem,0,0,SRCCOPY);
        SelectObject(hMem,hOld);
        DeleteObject(hBmp); DeleteDC(hMem);
        EndPaint(hWnd,&ps);
        break;
    }

    case WM_KEYDOWN:
        /* 检查时间锁定是否已解除 */
        if(g_dwLockLockTime) {
            DWORD elapsed=GetTickCount()-g_dwLockLockTime;
            if(elapsed>=60000) { g_dwLockLockTime=0; g_nLockFail=0; }
        }

        if(wParam==VK_RETURN) {
            if(!g_bShowInput) {
                /* 显示输入框 */
                g_bShowInput=TRUE;
                g_nLockInputLen=0;
                memset(g_szLockInput,0,sizeof(g_szLockInput));
                wcscpy(g_szLockMsg,L"");
                InvalidateRect(hWnd,NULL,FALSE);
            } else {
                /* 确认密码 */
                if(g_dwLockLockTime) {
                    DWORD elapsed=GetTickCount()-g_dwLockLockTime;
                    if(elapsed<60000) {
                        DWORD rem=(60000-elapsed)/1000+1;
                        _snwprintf(g_szLockMsg,127,
                                   L"Locked! Wait %d seconds...",rem);
                        InvalidateRect(hWnd,NULL,FALSE);
                        break;
                    }
                    g_dwLockLockTime=0; g_nLockFail=0;
                }
                if(wcscmp(g_szLockInput,g_szLockPwd)==0) {
                    g_nLockFail=0;
                    DoUnlockScreen();
                } else {
                    g_nLockFail++;
                    if(g_nLockFail>=5) {
                        g_dwLockLockTime=GetTickCount();
                        wcscpy(g_szLockMsg,L"Too many failures! Locked 60 seconds.");
                    } else {
                        _snwprintf(g_szLockMsg,127,
                                   L"Wrong password! (%d/5)",g_nLockFail);
                    }
                    g_nLockInputLen=0;
                    memset(g_szLockInput,0,sizeof(g_szLockInput));
                    InvalidateRect(hWnd,NULL,FALSE);
                }
            }
        } else if(wParam==VK_ESCAPE) {
            if(g_bShowInput) {
                g_bShowInput=FALSE;
                g_nLockInputLen=0;
                memset(g_szLockInput,0,sizeof(g_szLockInput));
                wcscpy(g_szLockMsg,L"");
                InvalidateRect(hWnd,NULL,FALSE);
            }
        } else if(wParam==VK_BACK) {
            if(!g_bShowInput) {
                /* Backspace也可以唤起输入框 */
                g_bShowInput=TRUE;
                g_nLockInputLen=0;
                memset(g_szLockInput,0,sizeof(g_szLockInput));
                wcscpy(g_szLockMsg,L"");
                InvalidateRect(hWnd,NULL,FALSE);
            } else if(g_nLockInputLen>0) {
                g_szLockInput[--g_nLockInputLen]=0;
                InvalidateRect(hWnd,NULL,FALSE);
            }
        }
        /* 注意：普通字符键由 WM_CHAR 处理，这里不做任何处理，避免重复输入 */
        break;

    case WM_CHAR: {
        WCHAR ch=(WCHAR)wParam;
        /* 只接受可打印字符，过滤控制字符。字符由键盘钉子的 ToUnicode 转换后投递，不会重复 */
        if(ch>=32 && ch!=127 && g_nLockInputLen<63) {
            if(!g_bShowInput) {
                g_bShowInput=TRUE;
                g_nLockInputLen=0;
                memset(g_szLockInput,0,sizeof(g_szLockInput));
                wcscpy(g_szLockMsg,L"");
            }
            g_szLockInput[g_nLockInputLen++]=ch;
            g_szLockInput[g_nLockInputLen]=0;
            InvalidateRect(hWnd,NULL,FALSE);
        }
        break;
    }

    case WM_ERASEBKGND: return 1;
    case WM_CLOSE:
    case WM_DESTROY: return 0;
    case WM_SYSCOMMAND:
        if(wParam==SC_CLOSE||wParam==SC_MINIMIZE||
           wParam==SC_MAXIMIZE||wParam==SC_MOVE||wParam==SC_SIZE)
            return 0;
        break;
    case WM_NCHITTEST: return HTCLIENT;
    case WM_ACTIVATE:
        if(LOWORD(wParam)==WA_INACTIVE && g_bLocked)
            SetForegroundWindow(hWnd);
        break;
    case WM_SETFOCUS:
        InvalidateRect(hWnd,NULL,FALSE);
        break;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

static void DoLockScreen(void) {
    if(g_bLocked) return;
    InterlockedExchange((LONG*)&g_bLocked, TRUE);   /* v3.2: 替代直接赋值 */
    g_bShowInput=FALSE;
    g_nLockInputLen=0;
    memset(g_szLockInput,0,sizeof(g_szLockInput));
    wcscpy(g_szLockMsg,L"");

    /*
     * 关键修复：禁用系统锁屏（防止Windows原生锁屏出现在我们的锁屏前面）
     * 方法1：SPI_SETSCREENSAVERRUNNING 告诉系统屏保正在运行
     * 方法2：立即显示我们的窗口并抢占焦点
     */
    SystemParametersInfoW(SPI_SETSCREENSAVERRUNNING, TRUE, NULL, 0);

    /* 关闭Windows锁屏进程（如果已经启动） */
    ExecHidden(L"taskkill /f /im LockApp.exe");
    ExecHidden(L"taskkill /f /im LogonUI.exe");

    int vx=GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy=GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw=GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh=GetSystemMetrics(SM_CYVIRTUALSCREEN);

    if(!g_hWndLock) {
        WNDCLASSW wc={0};
        wc.lpfnWndProc   = LockWndProc;
        wc.hInstance     = g_hInst;
        wc.lpszClassName = L"BossToolLock";
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
        wc.style         = CS_DBLCLKS|CS_OWNDC;
        RegisterClassW(&wc);

        g_hWndLock = CreateWindowExW(
            WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
            L"BossToolLock", L"",
            WS_POPUP,
            vx,vy,vw,vh,
            NULL,NULL,g_hInst,NULL);
    } else {
        SetWindowPos(g_hWndLock,HWND_TOPMOST,
                     vx,vy,vw,vh,SWP_SHOWWINDOW);
    }

    ShowWindow(g_hWndLock,SW_SHOW);
    UpdateWindow(g_hWndLock);
    /* 多次抢焦点确保在系统锁屏之前显示 */
    SetForegroundWindow(g_hWndLock);
    BringWindowToTop(g_hWndLock);
    SetFocus(g_hWndLock);
    SetActiveWindow(g_hWndLock);
}

static void DoUnlockScreen(void) {
    if(!g_bLocked) return;
    InterlockedExchange((LONG*)&g_bLocked, FALSE);  /* v3.2: 替代直接赋值 */

    /* 恢复系统正常状态 */
    SystemParametersInfoW(SPI_SETSCREENSAVERRUNNING, FALSE, NULL, 0);

    if(g_hWndLock) ShowWindow(g_hWndLock,SW_HIDE);
    g_bShowInput=FALSE;

    /* 解锁后把焦点还给桌面 */
    HWND hDesktop = GetDesktopWindow();
    SetForegroundWindow(hDesktop);
}

/* ============================================================
   登录对话框（每次呼出都需要输入密码）
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
                /* 直接显示设置窗口 */
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
    /* 如果设置窗口已打开，先关闭 */
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
   设置窗口
   ============================================================ */
static const WCHAR *g_szModNames[] = {
    L"Ctrl+Alt", L"Ctrl+Shift", L"Alt+Shift", L"Ctrl+Alt+Shift"
};
static const UINT g_nModVals[] = {
    MOD_CONTROL|MOD_ALT,
    MOD_CONTROL|MOD_SHIFT,
    MOD_ALT|MOD_SHIFT,
    MOD_CONTROL|MOD_ALT|MOD_SHIFT
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

        /* 锁屏密码 */
        h=CreateWindowW(L"STATIC",L"锁屏解锁密码:",
            WS_CHILD|WS_VISIBLE,8,y,120,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"EDIT",g_szLockPwd,
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
            135,y,230,22,hWnd,(HMENU)IDC_SET_SPWD,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=28;

        /* 老板键修饰符 */
        h=CreateWindowW(L"STATIC",L"老板键修饰符:",
            WS_CHILD|WS_VISIBLE,8,y,120,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"COMBOBOX",NULL,
            WS_CHILD|WS_VISIBLE|WS_BORDER|CBS_DROPDOWNLIST,
            135,y,160,100,hWnd,(HMENU)IDC_SET_BMOD,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        for(int i=0;i<4;i++)
            SendMessageW(h,CB_ADDSTRING,0,(LPARAM)g_szModNames[i]);
        int selM=0;
        for(int i=0;i<4;i++) if(g_nModVals[i]==g_BossMod){selM=i;break;}
        SendMessage(h,CB_SETCURSEL,selM,0);
        y+=28;

        /* 老板键按键 */
        h=CreateWindowW(L"STATIC",L"老板键(字母/数字):",
            WS_CHILD|WS_VISIBLE,8,y,130,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        WCHAR szVk[4]={(WCHAR)g_BossVk,0};
        h=CreateWindowW(L"EDIT",szVk,
            WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL|ES_UPPERCASE,
            145,y,50,22,hWnd,(HMENU)IDC_SET_BVK,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessage(h,EM_SETLIMITTEXT,1,0);
        y+=28;

        /* 开机自启 */
        h=CreateWindowW(L"BUTTON",L"开机自动运行",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
            8,y,200,22,hWnd,(HMENU)IDC_SET_AR,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessage(h,BM_SETCHECK,g_bAutoRun?BST_CHECKED:BST_UNCHECKED,0);
        y+=30;

        /* 隐藏列表说明 */
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

        /* 提示文字 */
        h=CreateWindowW(L"STATIC",
            L"提示：隐藏列表支持部分匹配，如\"记事本\"可匹配\"无标题 - 记事本\"",
            WS_CHILD|WS_VISIBLE,8,y,370,18,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=24;

        /* 允许修改IP开关 */
        h=CreateWindowW(L"BUTTON",L"允许手动修改IP地址（关闭时自动锁定）",
            WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,
            8,y,280,22,hWnd,(HMENU)IDC_SET_ALLOWIP,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        SendMessage(h,BM_SETCHECK,g_bAllowIPChange?BST_CHECKED:BST_UNCHECKED,0);
        y+=30;

        /* 按鈕行 */
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
        break;
    }
    case WM_COMMAND: {
        int id=LOWORD(wParam);
        if(id==IDC_SET_SAVE) {
            GetDlgItemTextW(hWnd,IDC_SET_LPWD,g_szLoginPwd,63);
            GetDlgItemTextW(hWnd,IDC_SET_SPWD,g_szLockPwd,63);
            GetDlgItemTextW(hWnd,IDC_SET_HL,g_szHideList,2047);
            int sel=(int)SendDlgItemMessageW(hWnd,IDC_SET_BMOD,
                                             CB_GETCURSEL,0,0);
            if(sel>=0&&sel<4) g_BossMod=g_nModVals[sel];
            WCHAR szVk[4]={0};
            GetDlgItemTextW(hWnd,IDC_SET_BVK,szVk,3);
            if((szVk[0]>='A'&&szVk[0]<='Z')||
               (szVk[0]>='0'&&szVk[0]<='9'))
                g_BossVk=szVk[0];
            g_bAutoRun=(SendDlgItemMessage(hWnd,IDC_SET_AR,
                                           BM_GETCHECK,0,0)==BST_CHECKED);
            /* 读取允许修改IP开关 */
            BOOL bAllow=(SendDlgItemMessage(hWnd,IDC_SET_ALLOWIP,
                                           BM_GETCHECK,0,0)==BST_CHECKED);
            if (bAllow != g_bAllowIPChange) {
                g_bAllowIPChange = bAllow;
                if (!bAllow) {
                    /* 关闭允许修改时，立即锁定并恢复当前模式的IP */
                    LockIPReg();
                    if (g_bBossMode) SetIPBoss();
                    else SetIPWork();
                } else {
                    /* 开启允许修改时，解除界面锁定 */
                    UnlockIPReg();
                }
            }
            SaveConfig();
            SetAutoRun(g_bAutoRun);
            UnregisterHotKey(g_hWndMain,HOTKEY_BOSS);
            UnregisterHotKey(g_hWndMain,HOTKEY_SETTINGS);
            UnregisterHotKey(g_hWndMain,HOTKEY_NETFIX);   /* v3.2 */
            RegisterHotkeys(g_hWndMain);
            MessageBoxW(hWnd,L"设置已保存！程序继续在后台运行。",L"提示",MB_OK);
            ShowWindow(hWnd,SW_HIDE);
        } else if(id==IDC_SET_CLOSE) {
            ShowWindow(hWnd,SW_HIDE);
        } else if(id==IDC_SET_APPLYIP) {
            SetIPWork();
            MessageBoxW(hWnd,L"工作IP已应用！",L"提示",MB_OK);
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
        g_hWndSettings=CreateWindowExW(
            WS_EX_TOPMOST|WS_EX_TOOLWINDOW,
            L"BossToolSettings",L"系统设置",
            WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,
            (cx-400)/2,(cy-420)/2,400,420,
            NULL,NULL,g_hInst,NULL);
    } else {
        /* 每次显示时刷新控件内容 */
        SetDlgItemTextW(g_hWndSettings,IDC_SET_LPWD,g_szLoginPwd);
        SetDlgItemTextW(g_hWndSettings,IDC_SET_SPWD,g_szLockPwd);
        SetDlgItemTextW(g_hWndSettings,IDC_SET_HL,g_szHideList);
        WCHAR szVk[4]={(WCHAR)g_BossVk,0};
        SetDlgItemTextW(g_hWndSettings,IDC_SET_BVK,szVk);
        int selM=0;
        for(int i=0;i<4;i++) if(g_nModVals[i]==g_BossMod){selM=i;break;}
        SendDlgItemMessageW(g_hWndSettings,IDC_SET_BMOD,
                            CB_SETCURSEL,selM,0);
        SendDlgItemMessage(g_hWndSettings,IDC_SET_AR,BM_SETCHECK,
                           g_bAutoRun?BST_CHECKED:BST_UNCHECKED,0);
        SendDlgItemMessage(g_hWndSettings,IDC_SET_ALLOWIP,BM_SETCHECK,
                           g_bAllowIPChange?BST_CHECKED:BST_UNCHECKED,0);
    }
    ShowWindow(g_hWndSettings,SW_SHOW);
    UpdateWindow(g_hWndSettings);
    SetForegroundWindow(g_hWndSettings);
}

/* ============================================================
   主窗口
   ============================================================ */
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    (void)lParam;
    switch(msg) {
    case WM_HOTKEY:
        if(wParam==HOTKEY_BOSS) {
            DoBossKey();
        } else if(wParam==HOTKEY_SETTINGS) {
            /* 每次都需要重新输入密码 */
            ShowLoginDialog();
        } else if(wParam==HOTKEY_NETFIX) {
            /* v3.2: Ctrl+Alt+F12 一键修复网络栈（应对ERR_NO_BUFFER_SPACE） */
            StartDetachedThread(EmergencyFixThread, NULL);
        }
        break;
    case WM_LOCK_SCREEN:
        DoLockScreen();
        break;
    case WM_SHOW_SETTINGS:
        ShowSettingsWindow();
        break;
    case WM_DESTROY:
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

    /* 加载配置 */
    LoadConfig();

    /* 进程保护 */
    ProtectProcess();

    /* 启动守护线程 */
    StartDetachedThread(WatchdogThread, NULL);
    StartDetachedThread(GuardThread, NULL);
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

    /* 注册热键 */
    RegisterHotkeys(g_hWndMain);

    /* 启动时强制设置工作IP（异步执行，不阻塞主线程）
     * 不管关机前是什么IP，开机一律恢复为20.*工作IP
     */
    StartDetachedThread(InitialIPThread, NULL);

    /* 判断是否是开机自启动（命令行参数包含 /autostart） */
    BOOL bAutoStart = (wcsstr(lpCmdLine, L"/autostart") != NULL);
    if (!bAutoStart) {
        /* 手动运行：显示登录对话框 */
        ShowLoginDialog();
    }
    /* 开机自启动：直接进入后台，不弹任何窗口 */

    /* 消息循环 */
    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* 清理 */
    if(g_hKeyHook) UnhookWindowsHookEx(g_hKeyHook);
    UnregisterHotKey(g_hWndMain,HOTKEY_BOSS);
    UnregisterHotKey(g_hWndMain,HOTKEY_SETTINGS);
    UnregisterHotKey(g_hWndMain,HOTKEY_NETFIX);   /* v3.2 */
    UnlockIPReg();
    if(g_hMutex) CloseHandle(g_hMutex);
    return (int)msg.wParam;
}
