/*
 * fix_acl_ultimate.c - 终极注册表ACL修复工具
 *
 * 方法：将自身注册为Windows服务，以SYSTEM权限运行，
 * 直接用 RegSetKeySecurity 重置两个被锁定的注册表键的安全描述符。
 *
 * SYSTEM权限是Windows最高权限，可以修改任何注册表键的ACL。
 *
 * 编译：
 *   x64: x86_64-w64-mingw32-gcc -O2 -municode -mwindows -o FixACLUltimate.exe fix_acl_ultimate.c -ladvapi32 -lshell32 -static
 *   x86: i686-w64-mingw32-gcc   -O2 -municode -mwindows -o FixACLUltimate_x86.exe fix_acl_ultimate.c -ladvapi32 -lshell32 -static
 */
#define _WIN32_WINNT 0x0601
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <wchar.h>
#include <stdio.h>
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>

/* 服务名称 */
#define SVC_NAME L"BossACLFix"

/* 日志路径（写到C:\Windows\Temp，SYSTEM可写） */
static WCHAR g_logPath[MAX_PATH];

static void Log(const WCHAR *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    WCHAR buf[1024];
    _vsnwprintf(buf, 1023, fmt, va);
    va_end(va);
    FILE *f = _wfopen(g_logPath, L"a");
    if (f) { fwprintf(f, L"%ls\n", buf); fclose(f); }
}

/*
 * 核心修复函数（以SYSTEM权限调用）
 * 使用 SDDL 构建完整的安全描述符，然后用 RegSetKeySecurity 写入
 */
static BOOL FixOneKey(HKEY hRoot, const WCHAR *subKeyPath) {
    Log(L"FixOneKey: %ls", subKeyPath);

    /* 启用所有特权 */
    HANDLE hTok;
    if (OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
        const WCHAR *privs[] = {
            SE_TAKE_OWNERSHIP_NAME,
            SE_RESTORE_NAME,
            SE_BACKUP_NAME,
            SE_SECURITY_NAME,
            SE_DEBUG_NAME
        };
        for (int i = 0; i < 5; i++) {
            TOKEN_PRIVILEGES tp;
            if (LookupPrivilegeValueW(NULL, privs[i], &tp.Privileges[0].Luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
            }
        }
        CloseHandle(hTok);
    }

    /* 构建安全描述符：
     * D:P = 保护型DACL（不继承父级）
     * (A;OICI;KA;;;WD)  = 允许Everyone完全控制，对象和容器继承
     * (A;OICI;KA;;;SY)  = 允许SYSTEM完全控制
     * (A;OICI;KA;;;BA)  = 允许Administrators完全控制
     * (A;OICI;KA;;;CO)  = 允许Creator Owner完全控制
     * O:SY              = 所有者为SYSTEM
     * G:SY              = 主组为SYSTEM
     */
    const WCHAR *sddl =
        L"O:SYG:SYD:P(A;OICI;KA;;;WD)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KA;;;CO)";

    PSECURITY_DESCRIPTOR pSD = NULL;
    ULONG sdSize = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, &sdSize)) {
        Log(L"  SDDL转换失败: %lu", GetLastError());
        return FALSE;
    }
    Log(L"  SDDL转换成功，SD大小=%lu", sdSize);

    /* 方法1：以 WRITE_OWNER | WRITE_DAC | KEY_ALL_ACCESS 打开 */
    HKEY hKey = NULL;
    LONG ret = RegOpenKeyExW(hRoot, subKeyPath, 0,
                             WRITE_OWNER | WRITE_DAC | KEY_ALL_ACCESS, &hKey);
    if (ret != ERROR_SUCCESS) {
        Log(L"  KEY_ALL_ACCESS打开失败(%ld)，尝试REG_OPTION_BACKUP_RESTORE...", ret);
        /* 方法2：使用备份/恢复标志绕过ACL检查 */
        ret = RegOpenKeyExW(hRoot, subKeyPath, REG_OPTION_BACKUP_RESTORE,
                            KEY_ALL_ACCESS, &hKey);
    }
    if (ret != ERROR_SUCCESS) {
        Log(L"  REG_OPTION_BACKUP_RESTORE也失败(%ld)，尝试NtSetSecurityObject...", ret);
        /* 方法3：直接用NtOpenKey + NtSetSecurityObject */
        typedef NTSTATUS (NTAPI *PFN_NtOpenKey)(PHANDLE, ACCESS_MASK, PVOID);
        typedef NTSTATUS (NTAPI *PFN_NtSetSec)(HANDLE, ULONG, PSECURITY_DESCRIPTOR);

        /* 构建OBJECT_ATTRIBUTES */
        typedef struct _UNICODE_STRING_NT {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING_NT;
        typedef struct _OBJECT_ATTRIBUTES {
            ULONG           Length;
            HANDLE          RootDirectory;
            UNICODE_STRING_NT *ObjectName;
            ULONG           Attributes;
            PVOID           SecurityDescriptor;
            PVOID           SecurityQualityOfService;
        } OBJECT_ATTRIBUTES_NT;

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        PFN_NtOpenKey  pfnNtOpenKey  = (PFN_NtOpenKey)GetProcAddress(hNtdll, "NtOpenKey");
        PFN_NtSetSec   pfnNtSetSec   = (PFN_NtSetSec)GetProcAddress(hNtdll, "NtSetSecurityObject");

        if (pfnNtOpenKey && pfnNtSetSec) {
            /* 构建完整的注册表路径 */
            WCHAR fullPath[1024];
            _snwprintf(fullPath, 1023, L"\\Registry\\Machine\\%ls", subKeyPath);
            UNICODE_STRING_NT uStr;
            uStr.Buffer = fullPath;
            uStr.Length = (USHORT)(wcslen(fullPath) * sizeof(WCHAR));
            uStr.MaximumLength = uStr.Length + sizeof(WCHAR);
            OBJECT_ATTRIBUTES_NT oa;
            ZeroMemory(&oa, sizeof(oa));
            oa.Length = sizeof(oa);
            oa.ObjectName = &uStr;
            oa.Attributes = 0x40; /* OBJ_CASE_INSENSITIVE */

            HANDLE hNtKey = NULL;
            NTSTATUS st = pfnNtOpenKey(&hNtKey, MAXIMUM_ALLOWED, &oa);
            Log(L"  NtOpenKey status=0x%08lX", (ULONG)st);
            if (st == 0 && hNtKey) {
                /* DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION = 5 */
                NTSTATUS st2 = pfnNtSetSec(hNtKey, 5, pSD);
                Log(L"  NtSetSecurityObject status=0x%08lX", (ULONG)st2);
                CloseHandle(hNtKey);
                LocalFree(pSD);
                return (st2 == 0);
            }
        }
        LocalFree(pSD);
        return FALSE;
    }

    /* 先设置所有者为SYSTEM */
    PSID pSystemSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 1,
            SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
        SECURITY_DESCRIPTOR sdOwner;
        InitializeSecurityDescriptor(&sdOwner, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorOwner(&sdOwner, pSystemSid, FALSE);
        LONG r2 = RegSetKeySecurity(hKey, OWNER_SECURITY_INFORMATION, &sdOwner);
        Log(L"  SetOwner result=%ld", r2);
        FreeSid(pSystemSid);
    }

    /* 设置DACL */
    ret = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pSD);
    Log(L"  RegSetKeySecurity(DACL) result=%ld", ret);

    RegCloseKey(hKey);
    LocalFree(pSD);

    if (ret == ERROR_SUCCESS) {
        /* 验证 */
        HKEY hVerify;
        LONG rv = RegOpenKeyExW(hRoot, subKeyPath, 0, KEY_WRITE, &hVerify);
        if (rv == ERROR_SUCCESS) {
            RegCloseKey(hVerify);
            Log(L"  验证通过：KEY_WRITE成功");
            return TRUE;
        } else {
            Log(L"  验证失败：KEY_WRITE返回%ld", rv);
        }
    }
    return (ret == ERROR_SUCCESS);
}

/* 修复所有相关键（包括ControlSet001/002/CurrentControlSet） */
static void FixAllKeys(void) {
    const WCHAR *guids[] = {
        L"{9a42de3d-70c3-4d77-936f-5c647562c960}",
        L"{c8de3d48-237f-4027-b846-02410c96cf5d}"
    };
    const WCHAR *controlSets[] = {
        L"SYSTEM\\CurrentControlSet",
        L"SYSTEM\\ControlSet001",
        L"SYSTEM\\ControlSet002"
    };

    for (int g = 0; g < 2; g++) {
        for (int c = 0; c < 3; c++) {
            WCHAR subKey[512];
            _snwprintf(subKey, 511,
                L"%ls\\Services\\Tcpip\\Parameters\\Interfaces\\%ls",
                controlSets[c], guids[g]);
            BOOL ok = FixOneKey(HKEY_LOCAL_MACHINE, subKey);
            Log(L"  %ls -> %ls", subKey, ok ? L"成功" : L"失败");
        }
    }

    /* 同时修复父键 */
    for (int c = 0; c < 3; c++) {
        WCHAR subKey[512];
        _snwprintf(subKey, 511,
            L"%ls\\Services\\Tcpip\\Parameters\\Interfaces",
            controlSets[c]);
        FixOneKey(HKEY_LOCAL_MACHINE, subKey);
    }

    Log(L"FixAllKeys done");
}

/* ============================================================
   服务模式（以SYSTEM权限运行）
   ============================================================ */
static SERVICE_STATUS        g_svcStatus;
static SERVICE_STATUS_HANDLE g_svcHandle;

static void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        g_svcStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_svcHandle, &g_svcStatus);
    }
}

static void WINAPI ServiceMain(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;

    g_svcHandle = RegisterServiceCtrlHandlerW(SVC_NAME, ServiceCtrlHandler);
    if (!g_svcHandle) return;

    g_svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwCurrentState = SERVICE_RUNNING;
    g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_svcHandle, &g_svcStatus);

    /* 以SYSTEM权限执行修复 */
    FixAllKeys();

    /* 完成，停止服务 */
    g_svcStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_svcHandle, &g_svcStatus);
}

/* ============================================================
   主程序（GUI模式，管理员权限）
   ============================================================ */
static void ShowResult(HWND hWnd, const WCHAR *msg) {
    MessageBoxW(hWnd, msg, L"BossTool ACL修复工具", MB_OK | MB_ICONINFORMATION);
}

static BOOL IsAdmin(void) {
    BOOL b = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION te; DWORD sz;
        if (GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &sz))
            b = te.TokenIsElevated;
        CloseHandle(hToken);
    }
    return b;
}

/* 安装并运行服务 */
static BOOL InstallAndRunService(const WCHAR *exePath) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        Log(L"OpenSCManager失败: %lu", GetLastError());
        return FALSE;
    }

    /* 删除旧服务 */
    SC_HANDLE hOld = OpenServiceW(hSCM, SVC_NAME, SERVICE_ALL_ACCESS);
    if (hOld) {
        SERVICE_STATUS ss;
        ControlService(hOld, SERVICE_CONTROL_STOP, &ss);
        Sleep(1000);
        DeleteService(hOld);
        CloseServiceHandle(hOld);
        Sleep(500);
    }

    /* 创建服务 */
    SC_HANDLE hSvc = CreateServiceW(
        hSCM, SVC_NAME, L"BossTool ACL Fix Service",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        exePath, NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        DWORD err = GetLastError();
        Log(L"CreateService失败: %lu", err);
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    Log(L"服务创建成功");

    /* 启动服务 */
    if (!StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        Log(L"StartService失败: %lu", err);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSCM);
        return FALSE;
    }
    Log(L"服务已启动，等待完成...");

    /* 等待服务停止（最多30秒） */
    for (int i = 0; i < 60; i++) {
        Sleep(500);
        SERVICE_STATUS ss;
        QueryServiceStatus(hSvc, &ss);
        if (ss.dwCurrentState == SERVICE_STOPPED) {
            Log(L"服务已完成（%d次轮询）", i);
            break;
        }
    }

    /* 删除服务 */
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return TRUE;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow) {
    (void)hInst; (void)hPrev; (void)nShow;

    /* 设置日志路径 */
    GetTempPathW(MAX_PATH, g_logPath);
    wcsncat(g_logPath, L"BossACLFix.log", MAX_PATH - wcslen(g_logPath) - 1);

    /* 检查是否以服务模式运行 */
    if (lpCmdLine && wcsstr(lpCmdLine, L"/service")) {
        /* 服务模式：注册服务主函数 */
        SERVICE_TABLE_ENTRYW svcTable[] = {
            { SVC_NAME, ServiceMain },
            { NULL, NULL }
        };
        StartServiceCtrlDispatcherW(svcTable);
        return 0;
    }

    /* GUI模式：检查管理员权限 */
    if (!IsAdmin()) {
        /* 请求UAC提权 */
        WCHAR exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        SHELLEXECUTEINFOW sei = {0};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = exePath;
        sei.nShow = SW_NORMAL;
        if (ShellExecuteExW(&sei)) {
            if (sei.hProcess) {
                WaitForSingleObject(sei.hProcess, INFINITE);
                CloseHandle(sei.hProcess);
            }
        } else {
            MessageBoxW(NULL, L"需要管理员权限！请右键以管理员身份运行。",
                        L"权限不足", MB_OK | MB_ICONERROR);
        }
        return 0;
    }

    /* 获取本程序路径 */
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    /* 构建服务命令行（带/service参数） */
    WCHAR svcCmdLine[MAX_PATH + 32];
    _snwprintf(svcCmdLine, MAX_PATH + 31, L"\"%ls\" /service", exePath);

    Log(L"=== BossTool ACL修复工具启动 ===");
    Log(L"exePath: %ls", exePath);

    /* 先尝试直接修复（当前进程可能已有足够权限） */
    Log(L"--- 尝试直接修复 ---");
    FixAllKeys();

    /* 验证是否成功 */
    BOOL directOK = FALSE;
    {
        HKEY hTest;
        LONG rv = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{9a42de3d-70c3-4d77-936f-5c647562c960}",
            0, KEY_WRITE, &hTest);
        if (rv == ERROR_SUCCESS) {
            RegCloseKey(hTest);
            directOK = TRUE;
        }
        Log(L"直接修复验证: %ls (ret=%ld)", directOK ? L"成功" : L"失败", rv);
    }

    if (!directOK) {
        /* 通过服务以SYSTEM权限修复 */
        Log(L"--- 通过服务修复 ---");
        MessageBoxW(NULL,
            L"正在安装修复服务（需要约15秒）...\n\n"
            L"请勿关闭此对话框，修复完成后会自动提示。",
            L"BossTool ACL修复工具",
            MB_OK | MB_ICONINFORMATION);

        BOOL svcOK = InstallAndRunService(svcCmdLine);
        Log(L"服务安装运行: %ls", svcOK ? L"成功" : L"失败");
    }

    /* 最终验证 */
    BOOL guid1OK = FALSE, guid2OK = FALSE;
    {
        HKEY hTest;
        LONG rv = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{9a42de3d-70c3-4d77-936f-5c647562c960}",
            0, KEY_WRITE, &hTest);
        if (rv == ERROR_SUCCESS) { RegCloseKey(hTest); guid1OK = TRUE; }
        Log(L"GUID1验证: %ls (ret=%ld)", guid1OK ? L"OK" : L"FAIL", rv);
    }
    {
        HKEY hTest;
        LONG rv = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{c8de3d48-237f-4027-b846-02410c96cf5d}",
            0, KEY_WRITE, &hTest);
        if (rv == ERROR_SUCCESS) { RegCloseKey(hTest); guid2OK = TRUE; }
        Log(L"GUID2验证: %ls (ret=%ld)", guid2OK ? L"OK" : L"FAIL", rv);
    }

    /* 复制日志到桌面 */
    WCHAR desktopLog[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopLog);
    wcsncat(desktopLog, L"\\BossACLFix_Log.txt", MAX_PATH - wcslen(desktopLog) - 1);
    CopyFileW(g_logPath, desktopLog, FALSE);

    if (guid1OK && guid2OK) {
        MessageBoxW(NULL,
            L"修复成功！\n\n"
            L"两个网络适配器注册表键的权限已恢复正常。\n"
            L"现在可以正常运行 BossTool.exe 了。\n\n"
            L"日志已保存到桌面：BossACLFix_Log.txt",
            L"修复成功", MB_OK | MB_ICONINFORMATION);
    } else {
        WCHAR msg[512];
        _snwprintf(msg, 511,
            L"修复结果：\n\n"
            L"GUID1 ({9a42de3d...}): %ls\n"
            L"GUID2 ({c8de3d48...}): %ls\n\n"
            L"如果仍然失败，请尝试：\n"
            L"1. 重启电脑后再次运行本工具\n"
            L"2. 进入安全模式运行本工具\n"
            L"3. 查看桌面日志：BossACLFix_Log.txt\n\n"
            L"也可以用 psexec -s -i regedit 手动修复",
            guid1OK ? L"成功" : L"失败",
            guid2OK ? L"成功" : L"失败");
        MessageBoxW(NULL, msg, L"修复结果", MB_OK | MB_ICONWARNING);
    }

    return 0;
}
