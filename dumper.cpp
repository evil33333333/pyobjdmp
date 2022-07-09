#include <Python.h>
#include <marshal.h>
#include <TlHelp32.h>
#include <fstream>
#include <array>
#include <iostream>
#include <vector>
#include <memory>
#include <string>

DWORD GetProcessId(std::wstring);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {

        HWND hwnd = GetConsoleWindow();


        // Add something the process name will contain 
        DWORD proc_id = GetProcessId(std::wstring(L"main.exe"));
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);

        // offset of the pyobject you want to dump
        uint64_t offset = 0x0000023FDBEEF0F0;
        PyObject* object = reinterpret_cast<PyObject*>(offset);

        size_t bytes_read;
        memset((void*)&bytes_read, 0x00, sizeof(size_t));

        std::array<unsigned char, sizeof(PyObject*) + 1> buffer{};

        // The ReadProcessMemory will check if it can read from the offsets location
        if (ReadProcessMemory(handle, (LPVOID)(offset), (LPVOID)buffer.data(), sizeof(PyObject*), &bytes_read))
        {
            std::cout << "\n[PyObjDmp] Valid offset was read." << std::endl;
            
            std::string filename = "0x" + std::to_string(offset) + ".bin";

            FILE* file = fopen(filename.c_str(), "wb");
            PyMarshal_WriteObjectToFile(object, file, Py_MARSHAL_VERSION);
            fclose(file);
            (void)MessageBoxA(hwnd, "Successfully Dumped PyObject", "PyObjDmp", MB_OK);
        }
        // If it can't, obviously we cannot get it.
        else
        {
            (void)MessageBoxA(hwnd, "Failure getting the PyObject pointer | Invalid Offset", "PyObjDmp", MB_ICONERROR);
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
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
