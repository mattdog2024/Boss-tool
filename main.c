/*
 * BossTool v3.3 - Windows 7/8/10/11 隐形管理工具
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
 * v3.2 真正修复 ERR_NO_BUFFER_SPACE：
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
#define HOTKEY_BOSS     1001
#define HOTKEY_SETTINGS 1002
#define HOTKEY_NETFIX   1003
#define HOTKEY_NETFIX_ALT 1004

#define EMERGENCY_MOD   (MOD_CONTROL|MOD_ALT)
#define EMERGENCY_VK    VK_F12
#define EMERGENCY_MOD_ALT (MOD_CONTROL|MOD_SHIFT)
#define EMERGENCY_VK_ALT  VK_F12

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
static volatile BOOL g_bEnableMacRandomization = FALSE;

/* 配置 */
static WCHAR g_szLoginPwd[64]   = DEFAULT_LOGIN_PWD;
static WCHAR g_szLockPwd[64]    = DEFAULT_LOCK_PWD;
static UINT  g_BossMod          = DEFAULT_BOSS_MOD;
static UINT  g_BossVk           = DEFAULT_BOSS_VK;
static BOOL  g_bAutoRun         = FALSE;
static WCHAR g_szHideList[2048] = L"";

/* v3.3: 隐私保险箱配置 */
static WCHAR g_szVaultPath[MAX_PATH] = L"";   /* .lvm 文件路径 */
static WCHAR g_szVaultPwd[128]       = L"";   /* BitLocker 密码（内存中明文，注册表中 XOR 混淆） */
static WCHAR g_szVaultDrive[4]       = L"";   /* 当前挂载的盘符，如 L"E:" */
static volatile BOOL g_bVaultMounted = FALSE; /* 是否已挂载 */

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
static void  SaveVaultConfig(void);
static void  LoadVaultConfig(void);
static WCHAR FindNewDriveLetter(DWORD dwBefore);
static DWORD GetAllDrives(void);
static BOOL  EnsureVirtualDiskService(void);
static BOOL  WaitForDriveLetter(DWORD dwBefore, WCHAR *pDrive, DWORD timeoutMs);

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
 * 核心挂载函数
 * 流程：
 *   1. 确保 Virtual Disk 服务运行
 *   2. 写 diskpart 脚本（UTF-16 LE BOM，解决中文路径问题）
 *   3. 执行 diskpart attach vdisk
 *   4. 等待新盘符出现（最多 20 秒）
 *   5. 用 manage-bde 解锁 BitLocker
 *   6. 记录挂载的盘符
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

    WriteLog(L"VaultMount: 开始挂载 [%ls]", g_szVaultPath);

    /* 步骤1: 确保 Virtual Disk 服务 */
    EnsureVirtualDiskService();

    /* 步骤2: 记录挂载前盘符 */
    DWORD dwBefore = GetAllDrives();

    /* 步骤3: 写 diskpart 脚本
     * 关键：必须用 UTF-16 LE BOM 写入，否则中文路径乱码
     * diskpart 在 Windows 10/11 上支持 UTF-16 脚本文件
     */
    WCHAR szScript[MAX_PATH];
    GetTempPathW(MAX_PATH, szScript);
    wcsncat(szScript, L"vaultmount.txt", MAX_PATH - wcslen(szScript) - 1);

    HANDLE hFile = CreateFileW(szScript, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WriteLog(L"VaultMount: 无法创建脚本文件 err=%lu", GetLastError());
        if (hWndParent)
            MessageBoxW(hWndParent, L"无法创建临时脚本文件！", L"错误",
                        MB_OK | MB_ICONERROR);
        return FALSE;
    }

    /* 写 BOM */
    BYTE bom[2] = {0xFF, 0xFE};
    DWORD written;
    WriteFile(hFile, bom, 2, &written, NULL);

    /* 写脚本内容（宽字符） */
    WCHAR szContent[1024];
    _snwprintf(szContent, 1023,
        L"select vdisk file=\"%ls\"\r\n"
        L"attach vdisk\r\n",
        g_szVaultPath);
    szContent[1023] = 0;
    WriteFile(hFile, szContent, (DWORD)(wcslen(szContent) * sizeof(WCHAR)),
              &written, NULL);
    CloseHandle(hFile);

    WriteLog(L"VaultMount: diskpart 脚本已写入 [%ls]", szScript);

    /* 步骤4: 执行 diskpart */
    WCHAR szCmd[MAX_PATH + 64];
    _snwprintf(szCmd, MAX_PATH + 63, L"diskpart /s \"%ls\"", szScript);
    szCmd[MAX_PATH + 63] = 0;

    DWORD exitCode = ExecHiddenEx(szCmd);
    WriteLog(L"VaultMount: diskpart 退出码=%lu", exitCode);

    /* 删除临时脚本 */
    DeleteFileW(szScript);

    /* 步骤5: 等待新盘符出现（最多 20 秒） */
    WCHAR cDrive = 0;
    if (!WaitForDriveLetter(dwBefore, &cDrive, 20000)) {
        WriteLog(L"VaultMount: 等待盘符超时，attach 失败");
        if (hWndParent) {
            WCHAR msg[512];
            _snwprintf(msg, 511,
                L"挂载失败！\r\n\r\n"
                L"诊断信息：\r\n"
                L"attach后无新盘符出现（等待20s超时）\r\n"
                L"diskpart退出码=%lu\r\n\r\n"
                L"可能原因：\r\n"
                L"1. 文件非有效VHDX格式\r\n"
                L"2. 需要管理员权限运行本程序\r\n"
                L"3. VDS(Virtual Disk)服务未运行\r\n"
                L"   Win+R → services.msc → Virtual Disk → 启动\r\n"
                L"4. 路径不能含中文（当前版本限制）\r\n\r\n"
                L"通用排查：\r\n"
                L"• 确认以管理员身份运行\r\n"
                L"• 确认VHD磁盘虚拟化服务已启动\r\n"
                L"• 路径不能含中文（当前版本限制）",
                exitCode);
            msg[511] = 0;
            MessageBoxW(hWndParent, msg, L"挂载失败！", MB_OK | MB_ICONERROR);
        }
        return FALSE;
    }

    WriteLog(L"VaultMount: 新盘符 %lc: 已出现", cDrive);

    /* 步骤6: 用 manage-bde 解锁 BitLocker */
    /* 等待盘符稳定 */
    Sleep(1000);

    WCHAR szUnlock[512];
    _snwprintf(szUnlock, 511,
        L"manage-bde -unlock %lc: -password",
        cDrive);
    szUnlock[511] = 0;

    /* manage-bde 需要从 stdin 读取密码，用管道方式传入 */
    /* 方法：echo 密码 | manage-bde -unlock X: -password */
    WCHAR szUnlockCmd[1024];
    _snwprintf(szUnlockCmd, 1023,
        L"echo %ls | manage-bde -unlock %lc: -password",
        g_szVaultPwd, cDrive);
    szUnlockCmd[1023] = 0;

    DWORD unlockExit = ExecHiddenEx(szUnlockCmd);
    WriteLog(L"VaultMount: manage-bde 解锁退出码=%lu", unlockExit);

    /* 等待解锁完成 */
    Sleep(2000);

    /* 验证盘符是否可访问 */
    WCHAR szTest[8];
    _snwprintf(szTest, 7, L"%lc:\\", cDrive);
    DWORD attrs = GetFileAttributesW(szTest);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        WriteLog(L"VaultMount: 解锁后盘符 %lc: 无法访问，可能密码错误", cDrive);
        if (hWndParent) {
            WCHAR msg[256];
            _snwprintf(msg, 255,
                L"VHDX 已挂载为 %lc:，但 BitLocker 解锁失败。\r\n"
                L"请检查密码是否正确。\r\n"
                L"manage-bde 退出码: %lu",
                cDrive, unlockExit);
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

    /* 步骤1: 先锁定 BitLocker（防止数据泄露） */
    if (g_szVaultDrive[0]) {
        WCHAR szLock[64];
        _snwprintf(szLock, 63, L"manage-bde -lock %ls -ForceDismount",
                   g_szVaultDrive);
        szLock[63] = 0;
        ExecHiddenEx(szLock);
        Sleep(500);
    }

    /* 步骤2: 写 diskpart detach 脚本（UTF-16 LE BOM） */
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
        _snwprintf(szContent, 1023,
            L"select vdisk file=\"%ls\"\r\n"
            L"detach vdisk\r\n",
            g_szVaultPath);
        szContent[1023] = 0;
        WriteFile(hFile, szContent, (DWORD)(wcslen(szContent) * sizeof(WCHAR)),
                  &written, NULL);
        CloseHandle(hFile);

        /* 步骤3: 执行 diskpart */
        WCHAR szCmd[MAX_PATH + 64];
        _snwprintf(szCmd, MAX_PATH + 63, L"diskpart /s \"%ls\"", szScript);
        szCmd[MAX_PATH + 63] = 0;
        DWORD exitCode = ExecHiddenEx(szCmd);
        WriteLog(L"VaultEject: diskpart detach 退出码=%lu", exitCode);

        DeleteFileW(szScript);
    }

    /* 步骤4: 等待盘符消失 */
    Sleep(2000);

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
    WriteLog(L"EmergencyNetworkFix: START");
    ExecHidden(L"net stop hns");
    ExecHidden(L"net stop iphlpsvc");
    ExecHidden(L"net stop nsi");
    Sleep(500);
    ExecHidden(L"net start nsi");
    ExecHidden(L"net start iphlpsvc");
    ExecHidden(L"net start hns");
    ExecHidden(L"ipconfig /flushdns");
    ExecHidden(L"netsh winsock reset catalog");
    WriteLog(L"EmergencyNetworkFix: DONE");
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

    const WCHAR *adpName = GetAdapterName();
    WCHAR cmd[512];
    _snwprintf(cmd, 511,
        L"wmic path win32_networkadapter where \"Name='%ls'\" call disable",
        adpName);
    ExecHidden(cmd);
    Sleep(2000);
    _snwprintf(cmd, 511,
        L"wmic path win32_networkadapter where \"Name='%ls'\" call enable",
        adpName);
    ExecHidden(cmd);
    Sleep(3000);
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

    /* 方案A: ipv4 + name + store=active */
    _snwprintf(args, 511,
        L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls store=active",
        adpName, ip1, mask1, gw);
    ret = RunNetshDirect(args);
    Sleep(1000);
    WriteLog(L"ApplyIP A ret=%lu", ret);
    if (ret == 0) bOK = TRUE;

    if (!bOK) {
        _snwprintf(args, 511,
            L"interface ipv4 set address name=\"%ls\" source=static addr=%ls mask=%ls gateway=%ls",
            adpName, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(1000);
        WriteLog(L"ApplyIP B ret=%lu", ret);
        if (ret == 0) bOK = TRUE;
    }

    if (!bOK && ifIdx > 0) {
        _snwprintf(args, 511,
            L"interface ip set address %lu static %ls %ls %ls 1",
            ifIdx, ip1, mask1, gw);
        ret = RunNetshDirect(args);
        Sleep(1000);
        WriteLog(L"ApplyIP C ret=%lu", ret);
    }

    if (ip2 && ip2[0]) {
        _snwprintf(args, 511,
            L"interface ipv4 add address name=\"%ls\" addr=%ls mask=%ls store=active",
            adpName, ip2, mask2);
        RunNetshDirect(args);
        Sleep(300);
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

static volatile BOOL g_bAllowIPChange = FALSE;
static WCHAR g_szExpectedIP[64] = {0};

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
            if (g_bBossMode)
                ApplyIP(IP_BOSS, IP_BOSS_MASK, IP_BOSS_GW, NULL, NULL, NULL);
            else
                ApplyIP(IP_WORK1, IP_WORK_MASK, IP_WORK_GW,
                        IP_WORK_DNS, IP_WORK2, IP_WORK_MASK);
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
    if (g_bEnableMacRandomization) RandomizeMac();
    wcsncpy(g_szExpectedIP, IP_WORK1, 63);
    ApplyIP(IP_WORK1, IP_WORK_MASK, IP_WORK_GW, IP_WORK_DNS, IP_WORK2, IP_WORK_MASK);
    LockIPReg();
    CloseNotepad();
    EndNetworkChange();
}

static void SetIPBoss(void) {
    if (!BeginNetworkChange()) return;
    if (g_bEnableMacRandomization) RandomizeMac();
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
    if (!RegisterHotKey(hWnd, HOTKEY_BOSS, g_BossMod, g_BossVk))
        WriteLog(L"RegisterHotKey BOSS failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_SETTINGS, SETTINGS_MOD, SETTINGS_VK))
        WriteLog(L"RegisterHotKey SETTINGS failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_NETFIX, EMERGENCY_MOD, EMERGENCY_VK))
        WriteLog(L"RegisterHotKey NETFIX failed err=%lu", GetLastError());
    if (!RegisterHotKey(hWnd, HOTKEY_NETFIX_ALT, EMERGENCY_MOD_ALT, EMERGENCY_VK_ALT))
        WriteLog(L"RegisterHotKey NETFIX_ALT failed err=%lu", GetLastError());
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
