// Build from a Visual Studio x64 Native Tools prompt at the repository root:
// cl /nologo /W3 /Od /Zi /I . tests\pdb_path.c /Fe:pdb_path.exe /link /DEBUG /PDB:pdb_path.pdb
// Run with the generated PDB, then a copy in a non-ASCII directory, using a UTF-8 ACP:
// pdb_path.exe pdb_path.pdb
// pdb_path.exe <non-ASCII-directory>\pdb_path.pdb

#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <valinet/pdb/pdb.h>

__declspec(noinline) int pdb_path_fixture(void)
{
    return 42;
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: pdb_path.exe <path-to-pdb_path.pdb>\n");
        return 2;
    }

    DWORD offset = 0;
    char* symbols[] = { "pdb_path_fixture" };
    INT result = VnGetSymbols(argv[1], &offset, symbols, 1);
    if (result != 0)
    {
        fprintf(stderr, "VnGetSymbols returned %d\n", result);
        return 1;
    }

    DWORD expected = (DWORD)((uintptr_t)pdb_path_fixture - (uintptr_t)GetModuleHandleW(NULL));
    if (offset != expected || pdb_path_fixture() != 42)
    {
        fprintf(stderr, "Unexpected offset: %lx (expected %lx)\n", offset, expected);
        return 1;
    }

    printf("Resolved pdb_path_fixture at %lx (ACP %u)\n", offset, GetACP());
    return 0;
}
