#ifndef _WIN32
#include "nhr_loader.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void *nhr_platform_open(const char *path, char *error, size_t error_size) {
    dlerror();
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle && error && error_size) {
        snprintf(error, error_size, "%s", dlerror() ? dlerror() : "dlopen failed");
    }
    return handle;
}

void nhr_platform_close(void *handle) {
    if (handle) dlclose(handle);
}

bool nhr_platform_copy(const char *source, const char *destination) {
    int in_fd, out_fd;
    char buffer[64 * 1024];
    ssize_t n;
    if (!source || !destination) return false;
    in_fd = open(source, O_RDONLY);
    if (in_fd < 0) return false;
    out_fd = open(destination, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out_fd < 0) { close(in_fd); return false; }
    while ((n = read(in_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t step = write(out_fd, buffer + written, (size_t)(n - written));
            if (step <= 0) { close(in_fd); close(out_fd); unlink(destination); return false; }
            written += step;
        }
    }
    bool ok = n == 0;
    close(in_fd);
    close(out_fd);
    if (!ok) unlink(destination);
    return ok;
}

bool nhr_platform_symbol(void *handle, const char *name,
                         void *destination, size_t destination_size,
                         char *error, size_t error_size) {
    void *symbol;
    const char *message;
    if (destination_size != sizeof(symbol)) {
        if (error && error_size) snprintf(error, error_size, "function pointer size mismatch");
        return false;
    }
    dlerror();
    symbol = dlsym(handle, name);
    message = dlerror();
    if (message || !symbol) {
        if (error && error_size) snprintf(error, error_size, "%s", message ? message : "symbol not found");
        return false;
    }
    memcpy(destination, &symbol, sizeof(symbol));
    return true;
}
#else
typedef int nhr_posix_translation_unit_is_not_empty;
#endif
