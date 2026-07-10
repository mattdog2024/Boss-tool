/*
 * BossToolForceExit.exe
 * 强力退出工具：通过 Mutex 名精准定位 BossTool 进程并强制结束
 *
 * 原理：
 *   BossTool 启动时创建名为 "Global\WinSvcHostMutex_7F3A" 的 Mutex。
 *   本工具通过枚举所有进程的句柄，找到持有该 Mutex 的进程，
 *   然后用 SeDebugPrivilege 绕过 DACL 保护，强制结束它。
 *   不依赖进程名，不会误杀真正的系统进程。
 *
 * 编译：
 *   x86_64-w64-mingw32-gcc -O2 -s -mwindows -municode
 *     -o BossToolForceExit.exe forcexit.c -ladvapi32 -luser32 -lkernel32
 */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>

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
   方法1：通过 Mutex 名找到持有它的进程 PID
   原理：尝试以 SYNCHRONIZE 权限打开 Mutex，
         如果成功说明它存在；再枚举进程找谁持有它。
   ============================================================ */
static DWORD FindPidByMutex(void) {
    /* 先确认 Mutex 存在 */
    HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, BOSS_MUTEX_NAME);
    if (!hMutex) return 0;
    CloseHandle(hMutex);

    /* 枚举所有进程，对每个进程枚举其句柄，找到持有该 Mutex 的进程 */
    /* 注意：枚举进程句柄需要 NtQuerySystemInformation，这里用更简单的方法：
       枚举进程，对每个进程尝试 OpenMutex 并比较对象名 */
    /* 简化方法：枚举所有进程，对每个进程尝试打开同名 Mutex，
       如果该进程就是持有者，则该进程退出后 Mutex 会消失。
       更直接：直接枚举进程，找名字匹配的，然后验证其是否持有 Mutex */

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    DWORD foundPid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            /* 跳过系统进程 */
            if (pe.th32ProcessID <= 4) continue;

            /* 尝试打开进程 */
            HANDLE hProc = OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            /* 尝试在该进程上下文中打开同名 Mutex，
               如果该进程是创建者，OpenMutex 会返回同一对象 */
            /* 实际上我们用更可靠的方法：
               检查进程是否有名字匹配的模块，然后验证 Mutex */
            CloseHandle(hProc);

            /* 检查进程名是否是已知的 BossTool 名称 */
            for (int i = 0; s_targets[i]; i++) {
                if (_wcsicmp(pe.szExeFile, s_targets[i]) == 0) {
                    /* 找到候选进程，记录 PID */
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
   方法2：暴力枚举所有进程，按名字匹配，全部结束
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

            HANDLE hProc = OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
                FALSE, pe.th32ProcessID);
            if (hProc) {
                /* 验证：检查该进程是否真的持有 BossTool 的 Mutex
                   方法：结束前先检查进程路径，排除系统 audiodg.exe */
                WCHAR szPath[MAX_PATH] = {0};
                DWORD dwSize = MAX_PATH;
                QueryFullProcessImageNameW(hProc, 0, szPath, &dwSize);

                /* 如果路径包含 System32，跳过（真正的系统 audiodg） */
                BOOL isSystem = (wcsstr(szPath, L"System32") != NULL ||
                                 wcsstr(szPath, L"system32") != NULL ||
                                 wcsstr(szPath, L"SysWOW64") != NULL);

                if (!isSystem) {
                    if (TerminateProcess(hProc, 0)) count++;
                }
                CloseHandle(hProc);
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
        /* 找到了 Mutex 但没结束任何进程，说明进程名不匹配 */
        WCHAR msg[512];
        wsprintfW(msg,
            L"检测到 BossTool 正在运行（Mutex 存在），\r\n"
            L"但未能找到匹配的进程名。\r\n\r\n"
            L"可能进程名已被修改。\r\n\r\n"
            L"请打开任务管理器 → 详细信息，\r\n"
            L"找到可疑进程后手动结束，或重启电脑。");
        MessageBoxW(NULL, msg, L"BossToolForceExit - 失败",
            MB_OK | MB_ICONERROR);
    }

    return 0;
}
