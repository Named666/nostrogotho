#include "log.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

/* Global verbosity level */
log_verbosity_t g_log_verbosity = LOG_VERBOSITY_QUIET; /* Default: ERROR only */

/* Initialize logging system */
void log_init(void) {
    /* Nothing to initialize for now */
}

/* Set verbosity level (0-3) */
void log_set_verbosity(log_verbosity_t verbosity) {
    if (verbosity > LOG_VERBOSITY_DEBUG) verbosity = LOG_VERBOSITY_DEBUG;
    g_log_verbosity = verbosity;
}

/* Get current verbosity level */
log_verbosity_t log_get_verbosity(void) {
    return g_log_verbosity;
}

/* Get current timestamp as string */
static void log_timestamp(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (tm && strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", tm)) {
        /* Success */
    } else {
        buf[0] = '\0';
    }
}

/* Get level string */
static const char *log_level_str(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO";
        case LOG_LEVEL_WARN:  return "WARN";
        case LOG_LEVEL_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

/* Core logging function - variadic version */
void log_v(log_level_t level, const char *component, const char *operation,
           const char *fmt, ...) {
    /* Check if this level should be printed at current verbosity */
    if (!log_should_print(level)) {
        return;
    }
    
    va_list args;
    va_start(args, fmt);
    
    char timestamp[32];
    log_timestamp(timestamp, sizeof(timestamp));
    
    /* Print timestamp */
    if (timestamp[0]) {
        fprintf(stdout, "[%s] ", timestamp);
    }
    
    /* Print level, component, operation */
    fprintf(stdout, "[%s] [%s] [%s] ", log_level_str(level), component, operation);
    
    /* Print formatted message */
    vfprintf(stdout, fmt, args);
    
    /* Newline and flush */
    fputc('\n', stdout);
    fflush(stdout);
    
    va_end(args);
}