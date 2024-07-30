#ifndef LIBVALINET_UTILITY_MEMMEM_H_
#define LIBVALINET_UTILITY_MEMMEM_H_
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// https://github.com/valinet/ssa/blob/master/KMP/c/kmp.c
inline void* memmem(void* haystack, size_t haystacklen, void* needle, size_t needlelen)
{
    const char* text = (const char*)haystack;
    const char* pattern = (const char*)needle;
    const char* rv = NULL;

    size_t* out = (size_t*)calloc(needlelen, sizeof(size_t));
    if (!out)
    {
        return NULL;
    }
    size_t j, i;

    j = 0, i = 1;
    while (i < needlelen) {
        if (text[j] != text[i])
        {
            if (j > 0)
            {
                j = out[j - 1];
                continue;
            }
            else j--;
        }
        j++;
        out[i] = j;
        i++;
    }

    i = 0, j = 0;
    for (i = 0; i <= haystacklen; i++) {
        if (text[i] == pattern[j]) {
            j++;
            if (j == needlelen) {
                rv = text + (int)(i - needlelen + 1); //match++; j = out[j - 1];
                break;
            }
        }
        else {
            if (j != 0) {
                j = out[j - 1];
                i--;
            }
        }
    }

    free(out);
    return (void*)rv;
}

#ifdef __cplusplus
}
#endif

#endif