// This will needed to be injected into the Cython exe via DLL injection.

#include "pch.h"
#include <Python.h>
#include <fstream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HANDLE handle = FindWindowA(NULL, "PROC");
        
        // offset in memory of the pyobject you want to dump
        long long offset = 0x2A747AA01F0;
        PyObject* object = nullptr;
        
        size_t bytes_read;
        memset((void*)&bytes_read, 0x00, sizeof(size_t));
        if (ReadProcessMemory(handle, (LPVOID)(offset), (LPVOID)&object, sizeof(PyObject*), &bytes_read)) {
            std::ofstream file("dumped_pyobject.bin");

            PyObject* _str = PyObject_Str(object);
            const char* data = PyUnicode_AsUTF8(_str);

            file.write(data, strlen(data));
            file.close();

            MessageBoxA(NULL, "Successfully Dumped PyObject", "cython killer", MB_OK);
        }
        else {
            MessageBoxA(NULL, "Failure getting the PyObject pointer", "cython killer", MB_ICONERROR);
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

