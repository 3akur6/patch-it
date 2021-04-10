#include "pch.h"
#include <detours.h>
#include <wchar.h>

extern "C"
{
    __declspec(dllexport) void dummy(void)
    {
        return;
    }
}

/// customized function for hooking DrawTextW, transforming PID from decimal to hex
int WINAPI MyDrawTextW(HDC hdc, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format);

static int (WINAPI * TrueDrawTextW)(HDC hdc, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format) = DrawTextW;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueDrawTextW, MyDrawTextW);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueDrawTextW, MyDrawTextW);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}

int WINAPI MyDrawTextW(HDC hdc, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format)
{
    size_t length = wcslen(lpchText); // length of raw text
    size_t converted_length = 0;
    WCHAR buffer[10];                 // buffer for _wtoi func

    // Check the first character to filter information that will cause _wtoi return 0 but actually isn't PID.
    // e.g.: "svchost.exe"
    if (lpchText[0] >= '0' && lpchText[0] <= '9')
    {
        // Convert raw text to integer. 
        // `_wtoi` func will convert string until character isn't among '0' and '9',
        // so `converted_length` must be less than `length` if it isn't
        unsigned int pid = _wtoi(lpchText);
        wsprintf(buffer, L"%d", pid);
        converted_length = wcslen(buffer);

        // PID is "n/a" or a decimal string,
        // so it can be identified by comparing `converted_length` and `length`.
        // If equal, PID
        if (converted_length == length)
        {
            WCHAR pid_hex[10];
            wsprintf(pid_hex, L"%X", pid);

            return TrueDrawTextW(hdc, pid_hex, cchText, lprc, format);
        }
    }

    return TrueDrawTextW(hdc, lpchText, cchText, lprc, format);
}