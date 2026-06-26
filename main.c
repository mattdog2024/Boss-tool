/*
 * BossTool v4.1 - Windows 7/8/10/11 隱形管理工具
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
 * v3.3.4 彻底修复 ERR_NO_BUFFER_SPACE + 兜底快捷键失效：
 *   - 根因：ApplyIP 每次 add address 不删除旧IP，导致IP地址累积耗尽网络栈缓冲区
 *   - ApplyIP 现在先 delete 所有旧IP，再 set/add 新IP，彻底消除累积
 *   - EmergencyNetworkFix 重写：暂停 IPGuard→清除累积 IP→重置网络栈→重新应用正确 IP
 *   - IPGuardThread 加 BeginNetworkChange/EndNetworkChange 保护
 *   - 兜底快捷键现在能真正恢复网络（不再被 IPGuard 立即覆盖）
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
#define IP_BOSS_DNS     L"8.2.27.254"

/* 热键ID */
#define HOTKEY_BOSS       1001
#define HOTKEY_SETTINGS   1002
#define HOTKEY_NETFIX     1003
#define HOTKEY_NETFIX_ALT 1004
#define HOTKEY_LOCK       1005   /* 锁屏热键 */

#define EMERGENCY_MOD     (MOD_CONTROL|MOD_ALT)
#define EMERGENCY_VK      VK_F12
#define EMERGENCY_MOD_ALT (MOD_CONTROL|MOD_SHIFT)
#define EMERGENCY_VK_ALT  VK_F12

/* 锁屏热键：Ctrl+Alt+L */
#define LOCK_MOD          (MOD_CONTROL|MOD_ALT)
#define LOCK_VK           'L'

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
#define IDC_SET_NETFIX   3013   /* v4.2.1: 紧急恢复网络按钮 */
#define IDC_SET_RANDMAC  3014   /* v4.2.1: 手动 MAC 随机化（危险，不推荐频繁用） */

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
static HWND      g_hWndLock     = NULL;
static HWND      g_hWndLogin    = NULL;
static HHOOK     g_hKeyHook     = NULL;
static HANDLE    g_hMutex       = NULL;

/* 状态标志 */
static volatile BOOL g_bBossMode = FALSE;
static volatile BOOL g_bLocked   = FALSE;
static volatile LONG g_lNetworkChangeBusy = 0;
static volatile LONG g_lEmergencyFixBusy  = 0;
/* v4.2.1: 删除 g_bEnableMacRandomization。MAC 随机化已不再是自动行为，
   改由用户在设置中手动触发（IDC_SET_RANDMAC），旧变量无任何引用。 */

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
LRESULT CALLBACK LockWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK KeyboardHookProc(int, WPARAM, LPARAM);
DWORD WINAPI     WatchdogThread(LPVOID);
DWORD WINAPI     GuardThread(LPVOID);
DWORD WINAPI     IPGuardThread(LPVOID);
DWORD WINAPI     BossKeyThread(LPVOID);
DWORD WINAPI     InitialIPThread(LPVOID);
DWORD WINAPI     EmergencyFixThread(LPVOID);
DWORD WINAPI     EmergencyFixFromButtonThread(LPVOID);  /* v4.2.1: 手动按钮触发，完成后弹提示框 */
DWORD WINAPI     RandomizeMacThread(LPVOID);  /* v4.2.1: 手动 MAC 随机化 */

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
static void EmergencyNetworkFix(void);

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
static BOOL  AdapterHasIP(const WCHAR *expectedIP);  /* v4.2.1: forward decl for EmergencyFixFromButtonThread */

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
    WCHAR buf[1024];
    va_list va;
    va_start(va, fmt);
    _vsnwprintf(buf, 1023, fmt, va);
    buf[1023] = 0;
    va_end(va);

    WCHAR szPath[MAX_PATH];
    GetTempPathW(MAX_PATH, szPath);
    wcsncat(szPath, L"bosstool.log", MAX_PATH - wcslen(szPath) - 1);

    HANDLE hFile = CreateFileW(szPath, GENERIC_WRITE, FILE_SHARE_READ,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        SYSTEMTIME st; GetLocalTime(&st);
        WCHAR line[1200];
        _snwprintf(line, 1199, L"[%02d:%02d:%02d] %ls\r\n",
                   st.wHour, st.wMinute, st.wSecond, buf);
        line[1199] = 0;
        DWORD written;
        /* 写 UTF-16 LE（Windows HANDLE 写入宽字符） */
        WriteFile(hFile, line, (DWORD)(wcslen(line)*sizeof(WCHAR)), &written, NULL);
        CloseHandle(hFile);
    }
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

    /* 读取输出（ANSI） */
    char ansiOut[1024] = {0};
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
/* v4.2.1: 本地化 EncodedCommand 风格的 PowerShell 安全执行器。
   为什么不在这里用 v4.2 P0 的 ExecPowerShellSafe：
   那个修复在独立分支上，本 commit 要能独立从 main 合入。
   代码复制一份是为了避免跨分支依赖。逻辑同 v4.2 (P0)。
   返回：脚本是否以 OK 退出。 */
static BOOL RunPSScriptEncoded(const WCHAR *psScript, DWORD *pdwExitCode) {
    if (pdwExitCode) *pdwExitCode = (DWORD)-1;
    if (!psScript || !*psScript) return FALSE;

    /* PowerShell.exe 路径 */
    WCHAR szPS[MAX_PATH] = {0};
    GetSystemDirectoryW(szPS, MAX_PATH);
    int cur = (int)wcslen(szPS);
    wcsncat(szPS, L"\\WindowsPowerShell\\v1.0\\powershell.exe",
            MAX_PATH - cur - 1);
    if (GetFileAttributesW(szPS) == INVALID_FILE_ATTRIBUTES) {
        WCHAR szWin[MAX_PATH] = {0};
        GetWindowsDirectoryW(szWin, MAX_PATH);
        _snwprintf(szPS, MAX_PATH - 1,
            L"%ls\\SysNative\\WindowsPowerShell\\v1.0\\powershell.exe", szWin);
    }

    /* UTF-16LE → base64（用 CryptBinaryToStringW） */
    DWORD byteLen = (DWORD)(wcslen(psScript) * sizeof(WCHAR));
    DWORD needed = 0;
    CryptBinaryToStringW((const BYTE*)psScript, byteLen,
                          CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                          NULL, &needed);
    if (needed <= 1) return FALSE;
    WCHAR *b64 = (WCHAR*)HeapAlloc(GetProcessHeap(), 0,
                                    needed * sizeof(WCHAR));
    if (!b64) return FALSE;
    if (!CryptBinaryToStringW((const BYTE*)psScript, byteLen,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              b64, &needed)) {
        HeapFree(GetProcessHeap(), 0, b64);
        return FALSE;
    }
    int b64Len = (int)wcslen(b64);

    WCHAR cmdLine[9000];
    _snwprintf(cmdLine, 8999,
        L"\"%ls\" -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand %ls",
        szPS, b64);
    cmdLine[8999] = 0;
    SecureZeroMemory(b64, needed * sizeof(WCHAR));
    HeapFree(GetProcessHeap(), 0, b64);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(szPS, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WriteLog(L"RunPSScriptEncoded: CreateProcess FAILED err=%lu", GetLastError());
        return FALSE;
    }
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    if (pdwExitCode) *pdwExitCode = exitCode;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

static void EmergencyNetworkFix(void) {
    /* ============================================================
       紧急网络修复 v4.2.1
       核心原则：绝不执行需要重启才能生效的命令！
       禁止：ipv4 reset / winsock reset / route flush /
             delete arpcache / delete destinationcache / delete address
       这些命令在不重启的情况下会让网络栈进入不一致状态，
       反而加重 ERR_NO_BUFFER_SPACE。

       v4.0 遗留问题：使用 netsh interface set interface ... admin=disabled
       在 Windows 10 1903+ 上已被微软废弃。很多驱动（USB 网卡、Wi-Fi、
       Hyper-V 虚拟网卡）会静默忽略这条命令，导致“紧急修复”实际上 noop。

       v4.2.1 修复：改用 PowerShell 官方 cmdlet Disable-NetAdapter /
       Enable-NetAdapter。微软官方推荐、对所有现代驱动都生效。

       正确策略（参考 AppHider EmergencyRestoreAsync）：
       1. PowerShell 禁用再启用网卡（硬重置，清空所有连接状态）
       2. 清空 DNS 客户端缓存、flush route 表
       3. 重新设置IP（用 set 覆盖，不 delete）
       4. 确保DNS服务运行
       5. 记录结果，返出后调用方可提示用户
       ============================================================ */

    /* 步骤0: 强制锁定，不等待（紧急修复优先级最高） */
    InterlockedExchange((LONG*)&g_lNetworkChangeBusy, 1);

    const WCHAR *adpName = GetAdapterName();
    WCHAR args[1024];
    WCHAR psScript[1024];
    DWORD psExitCode = 0;

    /* ----------------------------------------------------------
       步骤1: PowerShell 禁用网卡
       使用 Get-NetAdapter 拿 ifIndex，Disable-NetAdapter -Confirm:$false
       ---------------------------------------------------------- */
    _snwprintf(psScript, 1023,
        L"$n = Get-NetAdapter -Name '%ls' -ErrorAction SilentlyContinue; "
        L"if ($n) { "
        L"  Disable-NetAdapter -Name '%ls' -Confirm:$false -ErrorAction SilentlyContinue; "
        L"  Start-Sleep -Seconds 2; "
        L"  Enable-NetAdapter -Name '%ls' -Confirm:$false -ErrorAction SilentlyContinue; "
        L"  Start-Sleep -Seconds 3; "
        L"  Write-Output 'OK' "
        L"} else { "
        L"  Write-Output 'NOTFOUND' "
        L"}",
        adpName, adpName, adpName);
    psScript[1023] = 0;
    RunPSScriptEncoded(psScript, &psExitCode);
    WriteLog(L"EmergencyFix step1 (PS) exit=%lu", psExitCode);

    /* 备用：netsh 路径（驱动名不能用 PowerShell 时降级） */
    _snwprintf(args, 1023,
        L"interface set interface name=\"%ls\" admin=disabled",
        adpName);
    RunNetshDirect(args);
    Sleep(2000);
    _snwprintf(args, 1023,
        L"interface set interface name=\"%ls\" admin=enabled",
        adpName);
    RunNetshDirect(args);
    Sleep(3000);

    /* ----------------------------------------------------------
       步骤2: 清理 DNS 客户端缓存和 route 表
       （不需要重启，也不需要 winsock reset）
       ---------------------------------------------------------- */
    ExecHidden(L"ipconfig /flushdns");
    ExecHidden(L"route /f");

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
    InterlockedExchange((LONG*)&g_lNetworkChangeBusy, 0);
    WriteLog(L"EmergencyFix done");
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

/* v4.2.1: 从设置窗口按钮触发的紧急恢复。
   跟 EmergencyFixThread 的区别：完成后会弹一个明确的状态提示框。 */
static DWORD WINAPI EmergencyFixFromButtonThread(LPVOID p) {
    (void)p;
    /* g_lEmergencyFixBusy 已被 button handler 设置为 1，直接跑 */
    MessageBeep(MB_ICONEXCLAMATION);
    EmergencyNetworkFix();
    InterlockedExchange(&g_lEmergencyFixBusy, 0);
    MessageBeep(MB_OK);
    /* 检查当前 IP 是否已恢复 */
    BOOL ipOK = FALSE;
    if (g_szExpectedIP[0]) {
        ipOK = AdapterHasIP(g_szExpectedIP);
    }
    WCHAR msg[512];
    _snwprintf(msg, 511,
        L"紧急恢复已完成。\r\n\r\n"
        L"网卡：已禁用并启用（网络栈重置）\r\n"
        L"DNS 缓存：已清空\r\n"
        L"route 表：已清空\r\n"
        L"IP 重设：%ls\r\n\r\n"
        L"检测到期望 IP：%s\r\n\r\n"
        L"现在请试用一下网络。如果还是不行，请重启电脑。",
        g_bBossMode ? IP_BOSS : IP_WORK1,
        ipOK ? L"是" : L"否 （可能需要几秒才能生效）");
    msg[511] = 0;
    if (g_hWndSettings && IsWindow(g_hWndSettings)) {
        MessageBoxW(g_hWndSettings, msg, L"紧急恢复完成", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxW(NULL, msg, L"紧急恢复完成", MB_OK | MB_ICONINFORMATION);
    }
    return 0;
}

/* v4.2.1: 手动 MAC 随机化线程。
   SetIPBoss/SetIPWork 不再调用这个。只剩下用户从菜单主动触发。 */
static DWORD WINAPI RandomizeMacThread(LPVOID p) {
    (void)p;
    WriteLog(L"RandomizeMacThread: 手动触发");
    RandomizeMac();
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
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
}

/* ============================================================
   看门狗线程
   ============================================================ */
DWORD WINAPI WatchdogThread(LPVOID p) {
    (void)p;
    while (1) {
        Sleep(2000);
        if (g_bLocked) {
            HWND h;
            h = FindWindowW(L"TaskManagerWindow", NULL);
            if (h) PostMessage(h, WM_CLOSE, 0, 0);
            h = FindWindowW(L"#32770", L"Windows 任务管理器");
            if (h) PostMessage(h, WM_CLOSE, 0, 0);
        }
    }
    return 0;
}

/* ============================================================
   Guard 线程：锁屏时保持置顶
   ============================================================ */
DWORD WINAPI GuardThread(LPVOID p) {
    (void)p;
    while (1) {
        Sleep(500);
        if (g_bLocked && g_hWndLock && IsWindow(g_hWndLock)) {
            SetWindowPos(g_hWndLock, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }
    }
    return 0;
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
    Sleep(1500);
    _snwprintf(args, 511,
        L"interface set interface name=\"%ls\" admin=enabled",
        adpName);
    RunNetshDirect(args);
    Sleep(2000);
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

static void ApplyIP(const WCHAR *ip1, const WCHAR *mask1, const WCHAR *gw,
                    const WCHAR *dns, const WCHAR *ip2, const WCHAR *mask2) {
    const WCHAR *adpName = GetAdapterName();
    DWORD ifIdx = GetEthernetIfIndex();
    WCHAR args[512];
    BOOL bOK = FALSE;
    DWORD ret;

    /* v4.0 修复：不再 delete 旧IP！
     * delete address 会触发 Windows 释放所有绑定到该IP的socket，
     * 当有大量长连接时（浏览器几十个标签页），释放过程耗尽非分页池
     * → ERR_NO_BUFFER_SPACE (WSAENOBUFS 10055)
     *
     * 正确做法：直接用 set address 覆盖，Windows 会原子替换旧IP，
     * 不触发大规模socket释放。
     */
    WriteLog(L"ApplyIP: [adapter=%ls] ip=%ls", adpName, ip1);

    /* 方案A: ipv4 set address 直接覆盖（不delete） */
    _snwprintf(args, 511,
        L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls store=active",
        adpName, ip1, mask1, gw);
    ret = RunNetshDirect(args);
    Sleep(300);
    WriteLog(L"ApplyIP A ret=%lu", ret);
    if (ret == 0) bOK = TRUE;

    if (!bOK) {
        /* 方案B: 不带 store=active */
        _snwprintf(args, 511,
            L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls",
            adpName, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(300);
        WriteLog(L"ApplyIP B ret=%lu", ret);
        if (ret == 0) bOK = TRUE;
    }

    if (!bOK && ifIdx > 0) {
        /* 方案C: 用接口索引 */
        _snwprintf(args, 511,
            L"interface ip set address %lu static %ls %ls %ls 1",
            ifIdx, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(300);
        WriteLog(L"ApplyIP C ret=%lu", ret);
    }

    /* 第二IP：先尝试add，如果已存在会失败（无害） */
    if (ip2 && ip2[0]) {
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
    Sleep(5000);
    while (1) {
        Sleep(5000);
        if (g_bAllowIPChange || g_szExpectedIP[0] == 0) continue;
        if (g_lNetworkChangeBusy) continue;
        if (!AdapterHasIP(g_szExpectedIP)) {
            Sleep(15000);
            if (g_bAllowIPChange || g_szExpectedIP[0] == 0) continue;
            if (g_lNetworkChangeBusy || AdapterHasIP(g_szExpectedIP)) continue;
            /* v3.3.4: 用 BeginNetworkChange 保护，防止和 EmergencyFix 冲突 */
            if (!BeginNetworkChange()) continue;
            WriteLog(L"IPGuardThread: IP 丢失，重新应用");
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

static void SetIPWork(void) {
    if (!BeginNetworkChange()) return;
    /* v4.2.1: 不再自动 MAC 随机化。
     * 原因：每次切 IP 都 disable/enable 网卡会反复重置网络栈，nonpaged pool
     * 碎片化累积到一定阈值后，任何切 IP 操作都会引发 WSAENOBUFS (10055)。
     * 反复按老板键 10+ 次看不出问题，但中间用一阵子网络后再切，就 100% 报错。
     * MAC 随机化改为用户手动从菜单触发（仅在用户明确需要时执行）。 */
    wcsncpy(g_szExpectedIP, IP_WORK1, 63);
    ApplyIP(IP_WORK1, IP_WORK_MASK, IP_WORK_GW, IP_WORK_DNS, IP_WORK2, IP_WORK_MASK);
    LockIPReg();
    CloseNotepad();
    EndNetworkChange();
}

static void SetIPBoss(void) {
    if (!BeginNetworkChange()) return;
    /* v4.2.1: 同样去掉自动 MAC 随机化，见 SetIPWork 注释 */
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
    UnregisterHotKey(hWnd, HOTKEY_LOCK);
    if (!RegisterHotKey(hWnd, HOTKEY_BOSS, g_BossMod, g_BossVk))
        WriteLog(L"RegisterHotKey BOSS failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_SETTINGS, SETTINGS_MOD, SETTINGS_VK))
        WriteLog(L"RegisterHotKey SETTINGS failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_NETFIX, EMERGENCY_MOD, EMERGENCY_VK))
        WriteLog(L"RegisterHotKey NETFIX failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_NETFIX_ALT, EMERGENCY_MOD_ALT, EMERGENCY_VK_ALT))
        WriteLog(L"RegisterHotKey NETFIX_ALT failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_LOCK, LOCK_MOD, LOCK_VK)) {
        WriteLog(L"RegisterHotKey LOCK (Ctrl+Alt+L) failed err=%lu, trying Ctrl+Alt+K", GetLastError());
        /* Ctrl+Alt+L 可能被系统或其他程序占用，尝试备用键 */
        if (!RegisterHotKey(hWnd, HOTKEY_LOCK, LOCK_MOD, 'K'))
            WriteLog(L"RegisterHotKey LOCK (Ctrl+Alt+K) also failed err=%lu", GetLastError());
    }
}

/* ============================================================
   老板键逻辑
   ============================================================ */
DWORD WINAPI BossKeyThread(LPVOID pParam) {
    BOOL bEnterBoss = (BOOL)(ULONG_PTR)pParam;
    if (bEnterBoss) {
        /* 进入老板模式：切换IP + 隐藏程序 + 清理痕迹 + 挂载保险箱 */
        SetIPBoss();
        HideProcessWindows();
        CleanTraces();
        /* v3.3: 自动挂载保险箱 */
        VaultAutoMount();
    } else {
        /* 退出老板模式：弹出保险箱 + 恢复工作IP + 显示程序 + 清理痕迹 */
        /* v3.3: 先弹出保险箱（在切换IP之前，确保网络正常） */
        VaultAutoEject();
        SetIPWork();
        ShowProcessWindows();
        CleanTraces();
    }
    return 0;
}

DWORD WINAPI InitialIPThread(LPVOID pParam) {
    (void)pParam;

    /* v4.1: 禁用系统 Win+L 锁屏（组策略）
     * 这样 Win+L 不会触发 Windows 自带锁屏，而是被我们的键盘钩子拦截
     * 显示 Ubuntu 伪装界面。
     * 注册表路径: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
     * 值: DisableLockWorkstation = 1 */
    {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0, NULL, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            DWORD val = 1;
            RegSetValueExW(hKey, L"DisableLockWorkstation", 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
            RegCloseKey(hKey);
        }
    }

    /* v3.5: 启动时扫描并卸载旧版遗留的VHDX（更换版本后第一次运行） */
    VaultRecoverAndEject();
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
    if (nCode < 0) return CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);

    KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT*)lParam;
    UINT vk = kb->vkCode;
    BOOL bDown = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
    BOOL bCtrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    BOOL bAlt  = (GetAsyncKeyState(VK_MENU)    & 0x8000) != 0;
    BOOL bWin  = (GetAsyncKeyState(VK_LWIN)    & 0x8000) != 0 ||
                 (GetAsyncKeyState(VK_RWIN)    & 0x8000) != 0;

    /* v4.1: 拦截 Win+L，触发我们的 Ubuntu 伪装锁屏（而不是 Windows 自带锁屏） */
    if (!g_bLocked && bDown && bWin && vk == 'L') {
        /* 吃掉 Win+L，不传递给系统 */
        PostMessageW(g_hWndMain, WM_LOCK_SCREEN, 0, 0);
        return 1;
    }

    if (g_bLocked) {
        if (g_hWndLock && IsWindow(g_hWndLock)) {
            if (bDown) {
                if (vk == VK_RETURN) {
                    PostMessage(g_hWndLock, WM_KEYDOWN, VK_RETURN, 0);
                } else if (vk == VK_ESCAPE) {
                    PostMessage(g_hWndLock, WM_KEYDOWN, VK_ESCAPE, 0);
                } else if (vk == VK_BACK) {
                    PostMessage(g_hWndLock, WM_KEYDOWN, VK_BACK, 0);
                } else if (!bCtrl && !bAlt && !bWin) {
                    BYTE keyState[256] = {0};
                    GetKeyboardState(keyState);
                    WCHAR wchars[4] = {0};
                    int nChars = ToUnicode(vk, kb->scanCode, keyState, wchars, 3, 0);
                    if (nChars == 1 && wchars[0] >= 32 && wchars[0] != 127)
                        PostMessage(g_hWndLock, WM_CHAR, (WPARAM)wchars[0], 0);
                }
            }
        }
        return 1;
    }

    return CallNextHookEx(g_hKeyHook, nCode, wParam, lParam);
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

    HBRUSH hBk = CreateSolidBrush(RGB(0,0,0));
    FillRect(hdc, &rc, hBk);
    DeleteObject(hBk);
    SetBkMode(hdc, TRANSPARENT);

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

    HBRUSH hGreen = CreateSolidBrush(RGB(0,80,0));
    RECT rcBar = {0,0,W,26};
    FillRect(hdc, &rcBar, hGreen);
    DeleteObject(hGreen);
    SelectObject(hdc, hFTB);
    SetTextColor(hdc, RGB(200,255,200));
    WCHAR szTitle[] = L" Ubuntu 22.04.3 LTS  |  mediaserver-01  |  kernel 5.15.0-91-generic x86_64";
    TextOutW(hdc, 4, 5, szTitle, (int)wcslen(szTitle));

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

    int y = 108;
    int cols = (W-10)/9; if(cols>120)cols=120; if(cols<40)cols=40;
    WCHAR szSep[128];
    for(int i=0;i<cols&&i<127;i++) szSep[i]=L'='; szSep[cols]=0;
    SetTextColor(hdc, RGB(0,100,0));
    TextOutW(hdc, 5, y, szSep, cols); y+=18;

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

    _snwprintf(szLine,159,L"  hostname: mediaserver-01          uptime: %ls", szUptime);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,L"  os: Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)");
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
    _snwprintf(szLine,159,L"  services:  nginx[OK]  ffmpeg[OK]  rtmp[OK]  hls[OK]  redis[OK]");
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;
    _snwprintf(szLine,159,
        L"  streams: %d active  clients: %d connected  bitrate: %dkbps  dropped: %d/s",
        streams, clients, bitrate, dropped);
    TextOutW(hdc,5,y,szLine,(int)wcslen(szLine)); y+=17;

    SetTextColor(hdc, RGB(0,100,0));
    TextOutW(hdc,5,y,szSep,cols); y+=18;

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

    if(g_bShowInput) {
        int bx=(W-380)/2, by=(H-130)/2;
        if(bx<10) bx=10; if(by<10) by=10;
        HBRUSH hBr = CreateSolidBrush(RGB(0,15,0));
        RECT rcBox = {bx,by,bx+380,by+130};
        FillRect(hdc,&rcBox,hBr);
        DeleteObject(hBr);
        HPEN hPen = CreatePen(PS_SOLID,2,RGB(0,200,80));
        HPEN hOP = (HPEN)SelectObject(hdc,hPen);
        MoveToEx(hdc,bx,by,NULL); LineTo(hdc,bx+380,by);
        LineTo(hdc,bx+380,by+130); LineTo(hdc,bx,by+130); LineTo(hdc,bx,by);
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
        TextOutW(hdc,bx+10,by+90,L"[Enter]=confirm  [Esc]=cancel  [Backspace]=delete",49);
        TextOutW(hdc,bx+10,by+108,L"5 failures = 60s lockout",24);
    }

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
        DeleteObject(hBmp);
        DeleteDC(hMem);
        EndPaint(hWnd,&ps);
        break;
    }
    case WM_KEYDOWN:
        if(wParam==VK_RETURN) {
            if(!g_bShowInput) {
                g_bShowInput=TRUE;
                g_nLockInputLen=0;
                g_szLockInput[0]=0;
                g_szLockMsg[0]=0;
                InvalidateRect(hWnd,NULL,FALSE);
            } else {
                g_szLockInput[g_nLockInputLen]=0;
                if(g_dwLockLockTime && (GetTickCount()-g_dwLockLockTime)<60000) {
                    wcscpy(g_szLockMsg,L"Too many failures. Wait 60s.");
                    InvalidateRect(hWnd,NULL,FALSE);
                    break;
                }
                if(wcscmp(g_szLockInput,g_szLockPwd)==0) {
                    DoUnlockScreen();
                } else {
                    g_nLockFail++;
                    if(g_nLockFail>=5) {
                        g_dwLockLockTime=GetTickCount();
                        g_nLockFail=0;
                        wcscpy(g_szLockMsg,L"Locked 60s!");
                    } else {
                        _snwprintf(g_szLockMsg,127,L"Wrong password! (%d/5)",g_nLockFail);
                    }
                    g_nLockInputLen=0;
                    g_szLockInput[0]=0;
                    InvalidateRect(hWnd,NULL,FALSE);
                }
            }
        } else if(wParam==VK_ESCAPE) {
            if(g_bShowInput) {
                g_bShowInput=FALSE;
                g_nLockInputLen=0;
                g_szLockInput[0]=0;
                g_szLockMsg[0]=0;
                InvalidateRect(hWnd,NULL,FALSE);
            }
        } else if(wParam==VK_BACK) {
            if(g_bShowInput && g_nLockInputLen>0) {
                g_szLockInput[--g_nLockInputLen]=0;
                InvalidateRect(hWnd,NULL,FALSE);
            }
        }
        break;
    case WM_CHAR:
        if(g_bShowInput && wParam>=32 && wParam!=127 && g_nLockInputLen<63) {
            g_szLockInput[g_nLockInputLen++]=(WCHAR)wParam;
            g_szLockInput[g_nLockInputLen]=0;
            InvalidateRect(hWnd,NULL,FALSE);
        }
        break;
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
        if(!g_bShowInput) {
            g_bShowInput=TRUE;
            g_nLockInputLen=0;
            g_szLockInput[0]=0;
            g_szLockMsg[0]=0;
            InvalidateRect(hWnd,NULL,FALSE);
        }
        break;
    case WM_CLOSE:
        return 0;
    case WM_DESTROY:
        KillTimer(hWnd,1);
        break;
    }
    return DefWindowProcW(hWnd,msg,wParam,lParam);
}

/* ============================================================
   锁屏控制
   ============================================================ */
static void DoLockScreen(void) {
    if(g_bLocked) return;
    InterlockedExchange((LONG*)&g_bLocked, TRUE);
    g_bShowInput=FALSE;
    g_nLockFail=0;
    g_dwLockLockTime=0;
    g_szLockInput[0]=0;
    g_nLockInputLen=0;
    g_szLockMsg[0]=0;

    SystemParametersInfoW(SPI_SETSCREENSAVERRUNNING, TRUE, NULL, 0);
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
        SetWindowPos(g_hWndLock,HWND_TOPMOST,vx,vy,vw,vh,SWP_SHOWWINDOW);
    }
    ShowWindow(g_hWndLock,SW_SHOW);
    UpdateWindow(g_hWndLock);
    SetForegroundWindow(g_hWndLock);
    BringWindowToTop(g_hWndLock);
    SetFocus(g_hWndLock);
    SetActiveWindow(g_hWndLock);
}

static void DoUnlockScreen(void) {
    if(!g_bLocked) return;
    InterlockedExchange((LONG*)&g_bLocked, FALSE);
    SystemParametersInfoW(SPI_SETSCREENSAVERRUNNING, FALSE, NULL, 0);
    if(g_hWndLock) ShowWindow(g_hWndLock,SW_HIDE);
    g_bShowInput=FALSE;
    HWND hDesktop = GetDesktopWindow();
    SetForegroundWindow(hDesktop);
}

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

        /* v4.2.1: 紧急恢复网络按钮 —— 明显的大红块，使用 BS_DEFPUSHBUTTON 获得粗框 */
        h=CreateWindowW(L"BUTTON",
            L"\x2620 紧急恢复网络 (Ctrl+Alt+F12)",
            WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
            8,y,250,32,hWnd,(HMENU)IDC_SET_NETFIX,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        /* 说明文字 */
        h=CreateWindowW(L"STATIC",
            L"重置网络栈 + 重设 IP，遇到 ERR_NO_BUFFER_SPACE / 不能上网点这个",
            WS_CHILD|WS_VISIBLE,262,y+6,128,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=40;

        /* v4.2.1: 手动 MAC 随机化按钮（默认不跑。
           老板键不再自动随机化，避免反复 disable/enable 网卡 触发
           ERR_NO_BUFFER_SPACE。用户要要取奇小心点这个。 */
        h=CreateWindowW(L"BUTTON",
            L"\x2620 手动随机化 MAC（谨慎）",
            WS_CHILD|WS_VISIBLE,
            8,y,250,26,hWnd,(HMENU)IDC_SET_RANDMAC,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        h=CreateWindowW(L"STATIC",
            L"仅在需要彻底隐藏网络指纹时才点。会短暂断网。",
            WS_CHILD|WS_VISIBLE,262,y+4,128,20,hWnd,NULL,g_hInst,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hF,TRUE);
        y+=30;

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
        } else if(id==IDC_SET_NETFIX) {
            /* v4.2.1: 手动点 "紧急恢复网络" 按钮。
               异步跑，跑完后弹成功提示框（区别于 IPGuard 静默调用）。 */
            if (InterlockedCompareExchange(&g_lEmergencyFixBusy, 1, 0) != 0) {
                MessageBoxW(hWnd,
                    L"紧急恢复已在进行中，请等它完成（一般需 8–10 秒）。",
                    L"请稍候", MB_OK | MB_ICONINFORMATION);
                break;
            }
            MessageBoxW(hWnd,
                L"开始重置网络栈。\r\n\r\n"
                L"接下来 8–10 秒会出现：\r\n"
                L"  1. 网卡被禁用/启用（会断网 1–2 秒）\r\n"
                L"  2. 重新设置 IP、DNS\r\n"
                L"  3. 刷 DNS 缓存、route 表\r\n\r\n"
                L"完成后会弹一个提示框。",
                L"紧急恢复网络", MB_OK | MB_ICONINFORMATION);
            StartDetachedThread(EmergencyFixFromButtonThread, NULL);
        } else if(id==IDC_SET_RANDMAC) {
            /* v4.2.1: 手动触发 MAC 随机化。异步跑，避免 UI 冻结。 */
            if (MessageBoxW(hWnd,
                L"手动 MAC 随机化将：\r\n"
                L"  1. 写注册表修改网卡物理地址\r\n"
                L"  2. 禁用 + 启用网卡（会断网 3–5 秒）\r\n\r\n"
                L"频繁使用会累积网络栈问题（ERR_NO_BUFFER_SPACE 的根源之一）。\r\n"
                L"除非你明确知道为什么要点这个，否则请不要频繁使用。\r\n\r\n"
                L"确定要继续吗？",
                L"确认随机化 MAC", MB_YESNO | MB_ICONWARNING) != IDYES) {
                break;
            }
            StartDetachedThread(RandomizeMacThread, NULL);
        } else if(id==IDC_SET_SAVE) {
            /* 读取所有设置 */
            GetDlgItemTextW(hWnd,IDC_SET_LPWD,g_szLoginPwd,63);
            GetDlgItemTextW(hWnd,IDC_SET_SPWD,g_szLockPwd,63);
            GetDlgItemTextW(hWnd,IDC_SET_HL,g_szHideList,2047);
            int sel=(int)SendDlgItemMessageW(hWnd,IDC_SET_BMOD,CB_GETCURSEL,0,0);
            if(sel>=0&&sel<4) g_BossMod=g_nModVals[sel];
            WCHAR szVk[4]={0};
            GetDlgItemTextW(hWnd,IDC_SET_BVK,szVk,3);
            if((szVk[0]>='A'&&szVk[0]<='Z')||(szVk[0]>='0'&&szVk[0]<='9'))
                g_BossVk=szVk[0];
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
            (cx-400)/2,(cy-580)/2,400,580,
            NULL,NULL,g_hInst,NULL);
    } else {
        /* 刷新控件内容 */
        SetDlgItemTextW(g_hWndSettings,IDC_SET_LPWD,g_szLoginPwd);
        SetDlgItemTextW(g_hWndSettings,IDC_SET_SPWD,g_szLockPwd);
        SetDlgItemTextW(g_hWndSettings,IDC_SET_HL,g_szHideList);
        WCHAR szVk[4]={(WCHAR)g_BossVk,0};
        SetDlgItemTextW(g_hWndSettings,IDC_SET_BVK,szVk);
        int selM=0;
        for(int i=0;i<4;i++) if(g_nModVals[i]==g_BossMod){selM=i;break;}
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
    (void)lParam;
    switch(msg) {
    case WM_HOTKEY:
        if(wParam==HOTKEY_BOSS) {
            DoBossKey();
        } else if(wParam==HOTKEY_SETTINGS) {
            ShowLoginDialog();
        } else if(wParam==HOTKEY_NETFIX || wParam==HOTKEY_NETFIX_ALT) {
            StartDetachedThread(EmergencyFixThread, NULL);
        } else if(wParam==HOTKEY_LOCK) {
            PostMessageW(hWnd, WM_LOCK_SCREEN, 0, 0);
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

    /* 加载配置（含保险箱配置） */
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
