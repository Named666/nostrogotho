#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include "nhr_loader.h"
#include <stdio.h>
#include <string.h>

void *nhr_platform_open(const char *path, char *error, size_t error_size) {
    HMODULE module = LoadLibraryA(path);
    if (!module && error && error_size) {
        snprintf(error, error_size, "LoadLibraryA failed (error %lu)",
                 (unsigned long)GetLastError());
    }
    return (void *)module;
}

void nhr_platform_close(void *handle) {
    if (handle) FreeLibrary((HMODULE)handle);
}

bool nhr_platform_copy(const char *source, const char *destination) {
    return source && destination && CopyFileA(source, destination, FALSE) != 0;
}

bool nhr_platform_symbol(void *handle, const char *name,
                         void *destination, size_t destination_size,
                         char *error, size_t error_size) {
    FARPROC symbol = GetProcAddress((HMODULE)handle, name);
    if (!symbol) {
        if (error && error_size) {
            snprintf(error, error_size, "GetProcAddress failed (error %lu)",
                     (unsigned long)GetLastError());
        }
        return false;
    }
    if (destination_size != sizeof(symbol)) {
        if (error && error_size) snprintf(error, error_size, "function pointer size mismatch");
        return false;
    }
    memcpy(destination, &symbol, sizeof(symbol));
    return true;
}
#endif
