#ifndef LIBVALINET_HOOKING_IATPATCH_H_
#define LIBVALINET_HOOKING_IATPATCH_H_
#include <Windows.h>
#include <DbgHelp.h>
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
#include <stdio.h>
#endif
// https://blog.neteril.org/blog/2016/12/23/diverting-functions-windows-iat-patching/
inline BOOL VnPatchIAT(HMODULE module, PSTR libName, PSTR funcName, uintptr_t hookAddr)
{
    // Get a reference to the import table to locate the kernel32 entry
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);

    // In the import table find the entry that corresponds to kernel32
    BOOL found = FALSE;
    while (importDescriptor->Characteristics && importDescriptor->Name) {
        PSTR importName = (PSTR)((PBYTE)module + importDescriptor->Name);
        if (_stricmp(importName, libName) == 0) {
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
            printf("[PatchIAT] Found %s in IAT.\n", libName);
#endif
            found = TRUE;
            break;
        }
        importDescriptor++;
    }
    if (!found)
        return FALSE;

    // We use this value as a comparison
    HANDLE hMod = LoadLibraryA(libName);
    PROC baseFunc = (PROC)GetProcAddress(GetModuleHandleA(libName), funcName);

    // From the kernel32 import descriptor, go over its IAT thunks to
    // find the one used by the rest of the code to call GetProcAddress
    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((PBYTE)module + importDescriptor->FirstThunk);
    while (thunk->u1.Function) {
        PROC* funcStorage = (PROC*)&thunk->u1.Function;

        // Found it, now let's patch it
        if (*funcStorage == baseFunc) {
            // Get the memory page where the info is stored
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(funcStorage, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

            // Try to change the page to be writable if it's not already
            if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
                return FALSE;

            // Store our hook
            *funcStorage = (PROC)hookAddr;
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
            if ((*((WORD*)&(funcName)+1)))
            {
                printf("[PatchIAT] Patched %s in %s to 0x%p.\n", funcName, libName, hookAddr);
            }
            else
            {
                printf("[PatchIAT] Patched 0x%x in %s to 0x%p.\n", funcName, libName, hookAddr);
            }
#endif

            // Restore the old flag on the page
            DWORD dwOldProtect;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &dwOldProtect);

            // Profit
            return TRUE;
        }

        thunk++;
    }

    FreeLibrary(hMod);
    return FALSE;
}

// https://stackoverflow.com/questions/50973053/how-to-hook-delay-imports
inline BOOL VnPatchDelayIAT(HMODULE lib, PSTR libName, PSTR funcName, uintptr_t hookAddr)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lib;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)lib + dos->e_lfanew);
    PIMAGE_DELAYLOAD_DESCRIPTOR dload = (PIMAGE_DELAYLOAD_DESCRIPTOR)((uintptr_t)lib +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    while (dload->DllNameRVA)
    {
        char* dll = (char*)((uintptr_t)lib + dload->DllNameRVA);
        if (!_stricmp(dll, libName)) {
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
            printf("[PatchDelayIAT] Found %s in IAT.\n", libName);
#endif

            PIMAGE_THUNK_DATA firstthunk = (PIMAGE_THUNK_DATA)((uintptr_t)lib + dload->ImportNameTableRVA);
            PIMAGE_THUNK_DATA functhunk = (PIMAGE_THUNK_DATA)((uintptr_t)lib + dload->ImportAddressTableRVA);
            while (firstthunk->u1.AddressOfData)
            {
                if (firstthunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {}
                else {
                    PIMAGE_IMPORT_BY_NAME byName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)lib + firstthunk->u1.AddressOfData);
                    if (!_stricmp((char*)byName->Name, funcName)) {
                        DWORD oldProtect;
                        VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
                        functhunk->u1.Function = (uintptr_t)hookAddr;
                        VirtualProtect(&functhunk->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);
#ifdef _LIBVALINET_DEBUG_HOOKING_IATPATCH
                        printf("[PatchDelayIAT] Patched %s in %s to 0x%p.\n", funcName, libName, hookAddr);
#endif
                        return TRUE;
                    }
                }
                functhunk++;
                firstthunk++;
            }
        }
        dload++;
    }
    return FALSE;
}
#endif