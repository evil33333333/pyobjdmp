#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

DWORD get_pid(std::wstring);
void inject(DWORD procid, char* path);

int main() {
	DWORD pid = get_pid(std::wstring(L"PROC"));
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	char path[] = "fuck_cython.dll";
	inject(pid, path);
}

DWORD get_pid(std::wstring procname) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot && snapshot != INVALID_HANDLE_VALUE) 
	{
		PROCESSENTRY32 process_entry{};
		process_entry.dwSize = sizeof(process_entry);

		if (Process32First(snapshot, &process_entry)) {
			do
			{
				if (std::wstring(process_entry.szExeFile).find(procname) != std::wstring::npos) 
				{
					return process_entry.th32ProcessID;
				}
			} 
			while (Process32Next(snapshot, &process_entry));
		}
	}
}

void inject(DWORD procid, char* path) {
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, procid);
	HMODULE kernel_handle = GetModuleHandle(L"kernel32.dll");
	if (!kernel_handle)
		return;
	LPVOID load_lib_funcaddr = (LPVOID)GetProcAddress(kernel_handle, "LoadLibraryA");
	LPVOID load_path = VirtualAllocEx(handle, 0, strlen(path), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!load_path)
		return;
	HANDLE _rthread = CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)load_lib_funcaddr, load_path, NULL, NULL);
	if (!_rthread) {
		return;
	}
	WaitForSingleObject(_rthread, INFINITE);
	VirtualFreeEx(handle, load_path, strlen(path), MEM_RELEASE);
	CloseHandle(handle);
}
