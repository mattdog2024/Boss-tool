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

static int KillBossToolProcesses(void) {
    int killed = 0;
    DWORD selfPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == selfPid) continue;
            if (!IsBossToolProcess(pe.szExeFile)) continue;

            HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE,
                                      FALSE, pe.th32ProcessID);
            if (!proc) {
                proc = OpenProcess(PROCESS_TERMINATE,
                                   FALSE, pe.th32ProcessID);
            }
            if (proc) {
                if (TerminateProcess(proc, 1)) {
                    WaitForSingleObject(proc, 3000);
                    killed++;
                }
                CloseHandle(proc);
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return killed;
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
