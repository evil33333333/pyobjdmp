// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Python.h>
#include <TlHelp32.h>
#include <fstream>
#include <array>
#include <iostream>

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
        uint64_t offset = 0x1C5EC0425E0;
        PyObject* object = reinterpret_cast<PyObject*>(offset);

        size_t bytes_read;
        memset((void*)&bytes_read, 0x00, sizeof(size_t));

        std::array<unsigned char, sizeof(PyObject*) + 1> buffer{};

        // The ReadProcessMemory will check if it can read from the offsets location
        if (ReadProcessMemory(handle, (LPVOID)(offset), (LPVOID)buffer.data(), sizeof(PyObject*), &bytes_read))
        {
            std::cout << "\n[PyObjDmp] Valid offset was read." << std::endl;

            PyObject* repr = PyObject_Repr(object);
            PyObject* str = PyUnicode_AsEncodedString(repr, "utf-8", "~E~");
            const char* bytes = PyBytes_AS_STRING(str);
            
            
            if (!bytes)
            {
                MessageBeep(MB_ICONERROR);
                std::cout << "[PyObjDmp] PyObject* Returned NULL." << std::endl;
                (void)MessageBoxA(hwnd, "Failure getting the PyObject pointer | NULL BYTES", "PyObjDmp", MB_ICONERROR);
            }

            else
            {
                std::cout << "[PyObjDmp] Received " << strlen(bytes) << "bytes from this PyObject." << std::endl;
                std::ofstream file("dumped_pyobject.bin");
                file.write(bytes, strlen(bytes));
                file.close();

                (void)MessageBoxA(hwnd, "Successfully Dumped PyObject", "PyObjDmp", MB_OK);
            }
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
