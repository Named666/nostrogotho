#ifndef LOG_H_
#define LOG_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* ============================================================================
 * LOG.H - Structured Logging System
 * 
 * Provides structured logging with levels, components, operations, and key=value pairs.
 * Verbosity is controlled by relay_config_t.verbosity (0-3).
 * ============================================================================ */

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

/* Verbosity levels (for --debug flag)
 * 0 = ERROR only
 * 1 = ERROR + WARN
 * 2 = ERROR + WARN + INFO
 * 3 = ERROR + WARN + INFO + DEBUG
 */
typedef enum {
    LOG_VERBOSITY_QUIET = 0,   /* ERROR only */
    LOG_VERBOSITY_WARN  = 1,   /* ERROR + WARN */
    LOG_VERBOSITY_INFO  = 2,   /* ERROR + WARN + INFO */
    LOG_VERBOSITY_DEBUG = 3    /* ERROR + WARN + INFO + DEBUG (all) */
} log_verbosity_t;

/* Global verbosity level - set by relay or main via --debug flag */
extern log_verbosity_t g_log_verbosity;

/* Initialize logging system */
void log_init(void);

/* Set verbosity level (0-3) */
void log_set_verbosity(log_verbosity_t verbosity);

/* Get current verbosity level */
log_verbosity_t log_get_verbosity(void);

/* Check if a given log level should be printed at current verbosity */
static inline bool log_should_print(log_level_t level) {
    return level >= (log_level_t)(LOG_LEVEL_ERROR - g_log_verbosity);
}

/* Core logging function - variadic version */
void log_v(log_level_t level, const char *component, const char *operation,
           const char *fmt, ...);

/* Convenience macros for each level - verbosity checked inside log_v() */
#define log_debug(component, operation, fmt, ...) \
    log_v(LOG_LEVEL_DEBUG, component, operation, fmt, ##__VA_ARGS__)

#define log_info(component, operation, fmt, ...) \
    log_v(LOG_LEVEL_INFO, component, operation, fmt, ##__VA_ARGS__)

#define log_warn(component, operation, fmt, ...) \
    log_v(LOG_LEVEL_WARN, component, operation, fmt, ##__VA_ARGS__)

#define log_error(component, operation, fmt, ...) \
    log_v(LOG_LEVEL_ERROR, component, operation, fmt, ##__VA_ARGS__)

/* Ownership transfer logging */
#define log_ownership(function, type, ptr, from, to) \
    log_debug("OWNERSHIP", "TRANSFER", \
              "function=%s type=%s ptr=%p from=%s to=%s", \
              function, type, ptr, from, to)

/* Allocation logging */
#define log_alloc(function, type, ptr, size) \
    log_debug("MEMORY", "ALLOC", \
              "function=%s type=%s ptr=%p size=%zu", \
              function, type, ptr, size)

/* Free logging */
#define log_free(function, type, ptr) \
    log_debug("MEMORY", "FREE", \
              "function=%s type=%s ptr=%p", \
              function, type, ptr)

/* Connection logging helpers */
#define log_conn_info(conn_id, operation, fmt, ...) \
    log_info("RELAY", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

#define log_conn_debug(conn_id, operation, fmt, ...) \
    log_debug("RELAY", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

#define log_conn_warn(conn_id, operation, fmt, ...) \
    log_warn("RELAY", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

#define log_conn_error(conn_id, operation, fmt, ...) \
    log_error("RELAY", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

/* Subscription logging helpers */
#define log_sub_debug(conn_id, sub_id, operation, fmt, ...) \
    log_debug("SUBSCRIPTION", operation, "conn_id=%u sub_id=%s " fmt, \
              (unsigned)(conn_id), sub_id, ##__VA_ARGS__)

#define log_sub_info(conn_id, sub_id, operation, fmt, ...) \
    log_info("SUBSCRIPTION", operation, "conn_id=%u sub_id=%s " fmt, \
             (unsigned)(conn_id), sub_id, ##__VA_ARGS__)

#define log_sub_warn(conn_id, sub_id, operation, fmt, ...) \
    log_warn("SUBSCRIPTION", operation, "conn_id=%u sub_id=%s " fmt, \
             (unsigned)(conn_id), sub_id, ##__VA_ARGS__)

#define log_sub_error(conn_id, sub_id, operation, fmt, ...) \
    log_error("SUBSCRIPTION", operation, "conn_id=%u sub_id=%s " fmt, \
              (unsigned)(conn_id), sub_id, ##__VA_ARGS__)

/* Event logging helpers */
#define log_event_debug(conn_id, event_id, kind, operation, fmt, ...) \
    log_debug("EVENT", operation, "conn_id=%u event_id=%.16s kind=%d " fmt, \
              (unsigned)(conn_id), event_id, kind, ##__VA_ARGS__)

#define log_event_info(conn_id, event_id, kind, operation, fmt, ...) \
    log_info("EVENT", operation, "conn_id=%u event_id=%.16s kind=%d " fmt, \
             (unsigned)(conn_id), event_id, kind, ##__VA_ARGS__)

#define log_event_warn(conn_id, event_id, kind, operation, fmt, ...) \
    log_warn("EVENT", operation, "conn_id=%u event_id=%.16s kind=%d " fmt, \
             (unsigned)(conn_id), event_id, kind, ##__VA_ARGS__)

#define log_event_error(conn_id, event_id, kind, operation, fmt, ...) \
    log_error("EVENT", operation, "conn_id=%u event_id=%.16s kind=%d " fmt, \
              (unsigned)(conn_id), event_id, kind, ##__VA_ARGS__)

/* Storage logging helpers */
#define log_storage_debug(operation, fmt, ...) \
    log_debug("STORAGE", operation, fmt, ##__VA_ARGS__)

#define log_storage_info(operation, fmt, ...) \
    log_info("STORAGE", operation, fmt, ##__VA_ARGS__)

#define log_storage_warn(operation, fmt, ...) \
    log_warn("STORAGE", operation, fmt, ##__VA_ARGS__)

#define log_storage_error(operation, fmt, ...) \
    log_error("STORAGE", operation, fmt, ##__VA_ARGS__)

/* NIP/Module logging helpers */
#define log_nip_debug(nip_name, operation, fmt, ...) \
    log_debug("NIP", operation, "nip=%s " fmt, nip_name, ##__VA_ARGS__)

#define log_nip_info(nip_name, operation, fmt, ...) \
    log_info("NIP", operation, "nip=%s " fmt, nip_name, ##__VA_ARGS__)

#define log_nip_warn(nip_name, operation, fmt, ...) \
    log_warn("NIP", operation, "nip=%s " fmt, nip_name, ##__VA_ARGS__)

#define log_nip_error(nip_name, operation, fmt, ...) \
    log_error("NIP", operation, "nip=%s " fmt, nip_name, ##__VA_ARGS__)

/* NHR (Hot Reload) logging helpers */
#define log_nhr_debug(operation, fmt, ...) \
    log_debug("NHR", operation, fmt, ##__VA_ARGS__)

#define log_nhr_info(operation, fmt, ...) \
    log_info("NHR", operation, fmt, ##__VA_ARGS__)

#define log_nhr_warn(operation, fmt, ...) \
    log_warn("NHR", operation, fmt, ##__VA_ARGS__)

#define log_nhr_error(operation, fmt, ...) \
    log_error("NHR", operation, fmt, ##__VA_ARGS__)

/* Protocol logging helpers */
#define log_proto_debug(conn_id, operation, fmt, ...) \
    log_debug("PROTOCOL", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

#define log_proto_info(conn_id, operation, fmt, ...) \
    log_info("PROTOCOL", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

#define log_proto_warn(conn_id, operation, fmt, ...) \
    log_warn("PROTOCOL", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

#define log_proto_error(conn_id, operation, fmt, ...) \
    log_error("PROTOCOL", operation, "conn_id=%u " fmt, (unsigned)(conn_id), ##__VA_ARGS__)

/* Generic component logging */
#define log_component_debug(component, operation, fmt, ...) \
    log_debug(component, operation, fmt, ##__VA_ARGS__)

#define log_component_info(component, operation, fmt, ...) \
    log_info(component, operation, fmt, ##__VA_ARGS__)

#define log_component_warn(component, operation, fmt, ...) \
    log_warn(component, operation, fmt, ##__VA_ARGS__)

#define log_component_error(component, operation, fmt, ...) \
    log_error(component, operation, fmt, ##__VA_ARGS__)

#endif /* LOG_H_ */