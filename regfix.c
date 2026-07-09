/*
 * BossToolRegFix.exe
 * 一键修复工具：删除旧版 BossTool 遗留的 DisableLockWorkstation 注册表项
 * 修复 Win+L 按下后屏幕疯狂闪烁的问题
 *
 * 必须以管理员身份运行（程序会自动请求提权）
 */
#include <windows.h>
#include <wchar.h>

#define REG_PATH L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define REG_VAL  L"DisableLockWorkstation"

/* 检查是否以管理员身份运行 */
static BOOL IsElevated(void) {
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

/* 以管理员身份重新启动自身 */
static void RelaunchAsAdmin(void) {
    WCHAR szPath[MAX_PATH];
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = szPath;
    sei.nShow  = SW_SHOWNORMAL;
    ShellExecuteExW(&sei);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev,
                    LPWSTR lpCmdLine, int nCmdShow) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nCmdShow;

    /* 如果没有管理员权限，自动请求提权 */
    if (!IsElevated()) {
        RelaunchAsAdmin();
        return 0;
    }

    /* 尝试删除注册表项 */
    HKEY hKey = NULL;
    LONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_PATH,
                             0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);

    if (ret != ERROR_SUCCESS) {
        /* 注册表路径不存在，说明根本没有这个问题 */
        MessageBoxW(NULL,
            L"检测结果：未发现问题。\n\n"
            L"注册表中不存在 DisableLockWorkstation 项，\n"
            L"Win+L 应该可以正常使用。",
            L"BossToolRegFix", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    LONG delRet = RegDeleteValueW(hKey, REG_VAL);
    RegCloseKey(hKey);

    if (delRet == ERROR_SUCCESS) {
        MessageBoxW(NULL,
            L"修复成功！\n\n"
            L"已删除 DisableLockWorkstation 注册表项。\n"
            L"现在按 Win+L 可以正常锁屏，不会再闪烁。\n\n"
            L"无需重启电脑，立即生效。",
            L"BossToolRegFix", MB_OK | MB_ICONINFORMATION);
    } else if (delRet == ERROR_FILE_NOT_FOUND) {
        MessageBoxW(NULL,
            L"检测结果：未发现问题。\n\n"
            L"注册表中不存在 DisableLockWorkstation 项，\n"
            L"Win+L 应该可以正常使用。\n\n"
            L"如果仍然闪烁，请重启电脑后再试。",
            L"BossToolRegFix", MB_OK | MB_ICONINFORMATION);
    } else {
        WCHAR msg[256];
        wsprintfW(msg,
            L"删除失败（错误码 %ld）。\n\n"
            L"请手动删除：\n"
            L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n"
            L"值名称：DisableLockWorkstation",
            delRet);
        MessageBoxW(NULL, msg, L"BossToolRegFix", MB_OK | MB_ICONWARNING);
    }

    return 0;
}
