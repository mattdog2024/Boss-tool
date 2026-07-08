/*
 * BossToolKiller.exe
 * 专用工具：开启 SeDebugPrivilege 绕过 DACL 保护，结束 audiodg.exe 进程
 *
 * 原理：
 *   BossTool 用 DACL 拒绝了 Users 组的 PROCESS_TERMINATE 权限。
 *   但 Windows 有一个特权叫 SeDebugPrivilege（调试权限），
 *   开启它之后，OpenProcess 可以忽略 DACL 限制，直接拿到句柄。
 *   管理员账户默认拥有这个特权（只是没启用），启用后即可结束受保护进程。
 *
 * 编译：
 *   x86_64-w64-mingw32-gcc -O2 -s -mwindows -municode -o BossToolKiller.exe killer.c
 *                          -ladvapi32 -luser32 -lkernel32
 */

#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>

/* 目标进程名（伪装名） */
#define TARGET_EXE  L"audiodg.exe"
/* 备用：原始名，以防用户没有改名 */
#define TARGET_EXE2 L"BossTool.exe"

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
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)
              && GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

/* ============================================================
   按进程名查找并结束所有匹配进程
   返回结束的进程数量
   ============================================================ */
static int KillProcessByName(const WCHAR *name) {
    int count = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                /* 用 SeDebugPrivilege 绕过 DACL，强制打开句柄 */
                HANDLE hProc = OpenProcess(
                    PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
                    FALSE, pe.th32ProcessID);
                if (hProc) {
                    if (TerminateProcess(hProc, 0)) count++;
                    CloseHandle(hProc);
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

    /* 第二步：尝试结束目标进程（两个名字都试） */
    int n = KillProcessByName(TARGET_EXE);
    n    += KillProcessByName(TARGET_EXE2);

    /* 第三步：弹窗告知结果 */
    if (n > 0) {
        WCHAR msg[128];
        wsprintfW(msg, L"成功结束 %d 个 BossTool 进程。", n);
        MessageBoxW(NULL, msg, L"BossToolKiller", MB_OK | MB_ICONINFORMATION);
    } else {
        /* 没找到进程，或者权限不够 */
        WCHAR msg[256];
        if (!bPriv) {
            wsprintfW(msg,
                L"无法开启调试权限（SeDebugPrivilege）。\n\n"
                L"请右键本程序 → 以管理员身份运行。");
        } else {
            wsprintfW(msg,
                L"未找到 BossTool 进程（%ls / %ls）。\n\n"
                L"可能已经退出，或进程名已被修改。",
                TARGET_EXE, TARGET_EXE2);
        }
        MessageBoxW(NULL, msg, L"BossToolKiller", MB_OK | MB_ICONWARNING);
    }

    return 0;
}
