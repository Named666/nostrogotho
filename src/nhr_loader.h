#ifndef NHR_LOADER_H_
#define NHR_LOADER_H_

#include "nhr.h"

/* Platform-specific dynamic-loading primitives used by nhr.c. */
void *nhr_platform_open(const char *path, char *error, size_t error_size);
void nhr_platform_close(void *handle);
bool nhr_platform_copy(const char *source, const char *destination);
bool nhr_platform_symbol(void *handle, const char *name,
                         void *destination, size_t destination_size,
                         char *error, size_t error_size);

#endif /* NHR_LOADER_H_ */
