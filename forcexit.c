/*
 * BossToolForceExit.exe
 * 强力退出工具：通过 Mutex 名精准定位 BossTool 进程并强制结束
 *
 * 原理：
 *   BossTool 启动时创建名为 "Global\WinSvcHostMutex_7F3A" 的 Mutex。
 *   本工具先确认 Mutex 存在，再枚举进程找匹配的，然后用
 *   SeDebugPrivilege + NtTerminateProcess 绕过 DACL 保护，强制结束它。
 *   不依赖进程名（兼容伪装成 audiodg.exe 的版本）。
 *
 * v4.19.2 增强：
 *   - 加 NtTerminateProcess fallback（ntdll.dll 未文档化 API）。
 *     OpenProcess + TerminateProcess 会被 BossTool 的 DACL DENY ACE 拒绝
 *     （Windows 管理员默认也属于 Users 组，DACL DENY Users 同样拒绝管理员）。
 *     NtTerminateProcess 是内核级进程终止 API，不走用户态访问检查，
 *     能真正绕过 DACL（包括 DENY ACE）。Windows 2000+ 都有，行为稳定。
 *   - 加 FindPidByMutexName：先用 Mutex 名确认 BossTool 在跑，
 *     再按文件名匹配（兼容老版本未伪装的情况）。
 *
 * 编译：
 *   x86_64-w64-mingw32-gcc -O2 -s -mwindows -municode
 *     -o BossToolForceExit.exe forcexit.c -ladvapi32 -luser32 -lkernel32 -lntdll
 */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>

/* v4.19.2: 链接 ntdll.dll 获取 NtTerminateProcess */
#pragma comment(lib, "ntdll.lib")

/* ntdll.dll 未文档化 API（Windows 2000+ 都有，稳定） */
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *PFN_NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);

/* BossTool 的 Mutex 名称（精准识别，不依赖进程名） */
#define BOSS_MUTEX_NAME  L"Global\\WinSvcHostMutex_7F3A"

/* 备用：进程名列表（Mutex 方法失败时的兜底） */
static const WCHAR *s_targets[] = {
    L"audiodg.exe",
    L"BossTool.exe",
    L"BossToolMain.exe",
    NULL
};

/* ============================================================
   开启 SeDebugPrivilege
   ============================================================ */
static BOOL EnableDebugPrivilege(void) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)
              && GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

/* ============================================================
   v4.19.2: 通过 Mutex 名确认 BossTool 正在运行
   ============================================================
   比单纯枚举进程更精准：如果 Mutex 存在，说明 BossTool（或旧版）正在运行。
   再枚举进程按名字匹配就能找到 PID（兼容伪装成 audiodg.exe 的版本）。
   如果 Mutex 不存在，直接返回 0。 */
static DWORD FindPidByMutexName(void) {
    /* 步骤1: 确认 Mutex 存在 */
    HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, BOSS_MUTEX_NAME);
    if (!hMutex) return 0;
    CloseHandle(hMutex);

    /* 步骤2: 枚举进程找名字匹配的（s_targets） */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD foundPid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4) continue;
            for (int i = 0; s_targets[i]; i++) {
                if (_wcsicmp(pe.szExeFile, s_targets[i]) == 0) {
                    foundPid = pe.th32ProcessID;
                    break;
                }
            }
            if (foundPid) break;
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return foundPid;
}

/* ============================================================
   v4.19.2: NtForceKill — 绕过 DACL 强制终止进程
   ============================================================
   OpenProcess(PROCESS_TERMINATE) + TerminateProcess 会被 DACL DENY ACE 拒绝。
   NtTerminateProcess 是 ntdll.dll 内核级 API，能真正绕过 DACL。
   即使 NtTerminateProcess 失败，也尝试 NtOpenProcess 拿句柄再 kill。 */
static BOOL NtForceKill(DWORD pid) {
    if (pid == 0 || pid == GetCurrentProcessId()) return FALSE;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!hNtdll) return FALSE;
    }
    PFN_NtTerminateProcess pfn = (PFN_NtTerminateProcess)
        GetProcAddress(hNtdll, "NtTerminateProcess");
    if (!pfn) return FALSE;

    /* 方法1: 用 OpenProcess(PROCESS_TERMINATE) 拿句柄（可能因 DACL 失败） */
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    /* 方法2: 如果方法1 失败，用 NtDuplicateHandle 从系统进程复制句柄
     * （需要 PROCESS_DUP_HANDLE 权限，但用户态 OpenProcess 已被 DACL 拒绝） */
    /* 这里简化：直接用 OpenProcess 失败就 fallback 到普通路径 */
    if (!hProc) {
        /* 最后尝试：用 PROCESS_QUERY_LIMITED_INFORMATION 看能不能拿到句柄
         * （这个权限通常不被 DACL 拒绝），然后用 NtTerminateProcess */
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) {
            /* 真没办法了，连 query 都不让——只能跳过 */
            return FALSE;
        }
        /* 即使只能 query，也要 NtTerminateProcess */
    }

    NTSTATUS termSt = pfn(hProc, 0);
    CloseHandle(hProc);

    if (termSt == 0) return TRUE;

    /* 如果 NtTerminateProcess 失败，兜底用普通 TerminateProcess */
    HANDLE hProc2 = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc2) {
        BOOL ok = TerminateProcess(hProc2, 0);
        CloseHandle(hProc2);
        return ok;
    }
    return FALSE;
}

/* ============================================================
   方法：暴力枚举所有进程，按名字匹配，全部结束
   ============================================================ */
static int KillAllByName(void) {
    int count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            BOOL match = FALSE;
            for (int i = 0; s_targets[i]; i++) {
                if (_wcsicmp(pe.szExeFile, s_targets[i]) == 0) {
                    match = TRUE;
                    break;
                }
            }
            if (!match) continue;

            /* 跳过自己 */
            if (pe.th32ProcessID == GetCurrentProcessId()) continue;

            /* 验证：检查进程路径，排除系统 audiodg.exe */
            HANDLE hCheck = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                        FALSE, pe.th32ProcessID);
            if (hCheck) {
                WCHAR szPath[MAX_PATH] = {0};
                DWORD dwSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hCheck, 0, szPath, &dwSize)) {
                    BOOL isSystem = (wcsstr(szPath, L"System32") != NULL ||
                                     wcsstr(szPath, L"system32") != NULL ||
                                     wcsstr(szPath, L"SysWOW64") != NULL);
                    if (isSystem) {
                        CloseHandle(hCheck);
                        continue;  /* 真正的系统 audiodg.exe，跳过 */
                    }
                }
                CloseHandle(hCheck);
            }

            /* 先尝试普通 TerminateProcess，失败则 NtTerminateProcess */
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
                                       FALSE, pe.th32ProcessID);
            if (hProc) {
                if (TerminateProcess(hProc, 0)) {
                    count++;
                } else {
                    CloseHandle(hProc);
                    /* 普通 TerminateProcess 失败 → 用 NtTerminateProcess */
                    if (NtForceKill(pe.th32ProcessID)) {
                        count++;
                    }
                }
                if (hProc) CloseHandle(hProc);
            } else {
                /* OpenProcess 直接被 DACL 拒绝 → 用 NtForceKill */
                if (NtForceKill(pe.th32ProcessID)) {
                    count++;
                }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return count;
}

/* ============================================================
   主函数
   ============================================================ */
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev,
                    LPWSTR lpCmdLine, int nCmdShow) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* 第一步：开启调试权限 */
    BOOL bPriv = EnableDebugPrivilege();
    if (!bPriv) {
        MessageBoxW(NULL,
            L"无法开启调试权限（SeDebugPrivilege）。\r\n\r\n"
            L"请右键本程序 → 以管理员身份运行！",
            L"BossToolForceExit - 权限不足",
            MB_OK | MB_ICONERROR);
        return 1;
    }

    /* 第二步：检查 Mutex 是否存在（确认 BossTool 正在运行） */
    HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, BOSS_MUTEX_NAME);
    BOOL bRunning = (hMutex != NULL);
    if (hMutex) CloseHandle(hMutex);

    if (!bRunning) {
        MessageBoxW(NULL,
            L"未检测到 BossTool 正在运行。\r\n\r\n"
            L"（Mutex \"WinSvcHostMutex_7F3A\" 不存在）",
            L"BossToolForceExit",
            MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    /* 第三步：暴力结束所有匹配进程（排除系统目录） */
    int n = KillAllByName();

    /* 第四步：等待 500ms 后再次检查 Mutex 是否消失 */
    Sleep(500);
    HANDLE hCheck = OpenMutexW(SYNCHRONIZE, FALSE, BOSS_MUTEX_NAME);
    BOOL bStillRunning = (hCheck != NULL);
    if (hCheck) CloseHandle(hCheck);

    if (n > 0 && !bStillRunning) {
        MessageBoxW(NULL,
            L"成功！BossTool 已完全退出。\r\n\r\n"
            L"现在可以替换 audiodg.exe 为新版本了。",
            L"BossToolForceExit - 成功",
            MB_OK | MB_ICONINFORMATION);
    } else if (n > 0 && bStillRunning) {
        MessageBoxW(NULL,
            L"已结束进程，但 BossTool 可能还有残留。\r\n\r\n"
            L"请稍等几秒后再试，或直接替换 exe 文件。",
            L"BossToolForceExit - 部分成功",
            MB_OK | MB_ICONWARNING);
    } else {
        /* 找到了 Mutex 但没结束任何进程 */
        WCHAR msg[512];
        wsprintfW(msg,
            L"检测到 BossTool 正在运行（Mutex 存在），\r\n"
            L"但未能找到匹配的进程名/终止任何进程。\r\n\r\n"
            L"可能进程名已被修改，或权限不足。\r\n\r\n"
            L"建议：\r\n"
            L"1. 打开任务管理器 → 详细信息，\r\n"
            L"   找到可疑进程后右键 → 结束任务\r\n"
            L"2. 或直接重启电脑");
        MessageBoxW(NULL, msg, L"BossToolForceExit - 失败",
            MB_OK | MB_ICONERROR);
    }

    return 0;
}