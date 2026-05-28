/*
 * BossTool emergency exit tool.
 *
 * Finds all BossTool.exe and BossTool_x86.exe processes and forcefully exits
 * them. If the tool is not elevated, it relaunches itself as administrator.
 */

#define _WIN32_WINNT 0x0601
#define WINVER 0x0601
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <wchar.h>

#define MAX_TARGET_PIDS 256

static DWORD g_targetPids[MAX_TARGET_PIDS];
static int g_targetPidCount = 0;

static BOOL IsElevated(void) {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te;
        DWORD size = 0;
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size)) {
            elevated = te.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated;
}

static BOOL RelaunchAsAdmin(void) {
    WCHAR path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, path, MAX_PATH);

    SHELLEXECUTEINFOW sei;
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei);
}

static BOOL IsBossToolProcess(const WCHAR *name) {
    return _wcsicmp(name, L"BossTool.exe") == 0 ||
           _wcsicmp(name, L"BossTool_x86.exe") == 0;
}

static BOOL IsKnownBossWindow(const WCHAR *className, const WCHAR *title) {
    if (wcsncmp(className, L"BossTool", 8) == 0) return TRUE;
    if (wcscmp(title, L"\x7CFB\x7EDF\x8BBE\x7F6E") == 0) return TRUE;
    return FALSE;
}

static void AddTargetPid(DWORD pid) {
    if (!pid || pid == GetCurrentProcessId()) return;
    for (int i = 0; i < g_targetPidCount; i++) {
        if (g_targetPids[i] == pid) return;
    }
    if (g_targetPidCount < MAX_TARGET_PIDS) {
        g_targetPids[g_targetPidCount++] = pid;
    }
}

static BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    (void)lParam;
    WCHAR className[256] = {0};
    WCHAR title[512] = {0};
    DWORD pid = 0;

    GetClassNameW(hWnd, className, 255);
    GetWindowTextW(hWnd, title, 511);
    GetWindowThreadProcessId(hWnd, &pid);

    if (IsKnownBossWindow(className, title)) {
        AddTargetPid(pid);
    }

    return TRUE;
}

static BOOL CollectBossToolProcessesByName(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (IsBossToolProcess(pe.szExeFile)) {
                AddTargetPid(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return TRUE;
}

static int KillCollectedProcesses(void) {
    int killed = 0;
    for (int i = 0; i < g_targetPidCount; i++) {
        HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE,
                                  FALSE, g_targetPids[i]);
        if (!proc) {
            proc = OpenProcess(PROCESS_TERMINATE, FALSE, g_targetPids[i]);
        }
        if (proc) {
            if (TerminateProcess(proc, 1)) {
                WaitForSingleObject(proc, 3000);
                killed++;
            }
            CloseHandle(proc);
        }
    }
    return killed;
}

static int KillBossToolProcesses(void) {
    g_targetPidCount = 0;
    BOOL byNameOK = CollectBossToolProcessesByName();
    EnumWindows(EnumWindowsProc, 0);
    if (!byNameOK && g_targetPidCount == 0) return -1;
    return KillCollectedProcesses();
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInst,
                    LPWSTR lpCmdLine, int nCmdShow) {
    (void)hInstance;
    (void)hPrevInst;
    (void)lpCmdLine;
    (void)nCmdShow;

    if (!IsElevated()) {
        if (RelaunchAsAdmin()) return 0;
        MessageBoxW(NULL,
                    L"Administrator permission is required to force close BossTool.",
                    L"BossTool Emergency Exit",
                    MB_OK | MB_ICONERROR);
        return 1;
    }

    int killed = KillBossToolProcesses();
    WCHAR msg[256];
    if (killed < 0) {
        wcscpy(msg, L"Could not read the process list. Please try again.");
        MessageBoxW(NULL, msg, L"BossTool Emergency Exit",
                    MB_OK | MB_ICONERROR);
        return 2;
    }

    _snwprintf(msg, 255,
               L"Force closed %d BossTool process(es).\n\nYou can now run the new BossTool.exe.",
               killed);
    msg[255] = 0;
    MessageBoxW(NULL, msg, L"BossTool Emergency Exit",
                MB_OK | MB_ICONINFORMATION);
    return 0;
}
