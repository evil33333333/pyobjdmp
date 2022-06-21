#include <iostream>
#include <windows.h>
#include <TlHelp32.h>

DWORD GetProcessId(std::wstring);
void RemoteThreadInjection(DWORD, char*);

int main() {
	DWORD process_id = GetProcessId(std::wstring(L"main.exe"));
	std::cout << "[+] Grabbed Process ID: " << process_id << std::endl;

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
	std::cout << "[+] Opened the process." << std::endl;

	char path[] = "fuck_cython.dll";

	std::cout << "[@] Starting injection..." << std::endl;
	RemoteThreadInjection(process_id, path);
}

DWORD GetProcessId(std::wstring procname) {
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
			} while (Process32Next(snapshot, &process_entry));
		}
	}
}

void RemoteThreadInjection(DWORD procid, char* path) {
	size_t pathlen = strlen(path) + 1;
	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, procid);
	HMODULE kernel_handle = GetModuleHandle(L"kernel32.dll");
	if (!kernel_handle)
	{
		std::cout << "[!] Could not get the kernel module handle :(" << std::endl;
		CloseHandle(handle);
		return;
	}
		
	LPVOID load_lib_funcaddr = (LPVOID)GetProcAddress(kernel_handle, "LoadLibraryA");
	LPVOID load_path = VirtualAllocEx(handle, 0, pathlen, MEM_COMMIT, PAGE_READWRITE);
	if (!load_path)
	{
		std::cout << "[!] Could not allocate memory for the DLL path :(" << std::endl;
		CloseHandle(handle);
		return;
	}

	bool written_memory = WriteProcessMemory(handle, load_path, path, pathlen, 0);
	if (!written_memory)
	{
		std::cout << "[!] Could not write process memory :(" << std::endl;
		CloseHandle(handle);
		return;
	}
		
	HANDLE remote_thread = CreateRemoteThread(handle, 0, 0, (LPTHREAD_START_ROUTINE)load_lib_funcaddr, load_path, 0, 0);
	if (!remote_thread)
	{
		std::cout << "[!] Could not create remote thread :(" << std::endl;
		VirtualFreeEx(handle, load_path, 0, MEM_RELEASE);
		CloseHandle(handle);
		return;
	}
	MessageBeep(MB_OK);
	std::cout << "[!] Injected PyObject dumper successfully!" << std::endl;
	WaitForSingleObject(remote_thread, INFINITE);

	std::cout << "[!] Finished extraction." << std::endl;
	VirtualFreeEx(handle, load_path, 0, MEM_RELEASE);
	CloseHandle(handle);
}
