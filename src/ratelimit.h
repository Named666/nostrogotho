/* ratelimit - per-IP / per-pubkey rate limits and ban lists.
 *
 * Rate limits are GCRA token buckets ("generic cell rate algorithm": one
 * 64-bit theoretical-arrival time per bucket) updated with a CAS loop, so
 * the hot path takes no lock and every worker shares one budget per key.
 * Keys hash into two rows of a fixed table (count-min): a request is
 * refused only when both of its buckets are exhausted, so a hash collision
 * can never throttle a key that is under its own rate. The hash is seeded
 * at startup (collisions cannot be precomputed).
 *
 * Ban lists (pubkeys, IPs) are sorted arrays built once at startup from
 * nostrogotho.conf and the optional ban_file; lookups are lock-free binary
 * searches. IPv6 addresses are limited per /64.
 *
 * Threading: rl_configure runs single-threaded at startup; everything else
 * is safe from any thread.
 */
#ifndef RATELIMIT_H_
#define RATELIMIT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ng_status.h"

typedef enum { RL_EVENT_IP, RL_EVENT_PUBKEY, RL_REQ_IP, RL_CLASSES } rl_class_t;

typedef struct {
    int per_min[RL_CLASSES];    /* sustained rate per key, 0 = unlimited */
    int burst[RL_CLASSES];      /* bucket depth (>= 1) */
    const char *banned_pubkeys; /* comma/space separated hex pubkeys (or NULL) */
    const char *banned_ips;     /* comma/space separated IPv4/IPv6 addresses (or NULL) */
    const char *ban_file;       /* path: lines "pubkey <hex>" / "ip <addr>", # comments */
    /* Reverse proxies whose X-Forwarded-For / X-Real-IP are believed:
     * comma/space separated addresses or CIDR prefixes ("10.0.0.0/8").
     * NULL = RL_TRUSTED_PROXIES_DEFAULT, "" = none. */
    const char *trusted_proxies;
} rl_config_t;

#define RL_TRUSTED_PROXIES_DEFAULT "127.0.0.1,::1"

/* Startup. NG_E_INVALID (with *bad_line set for the ban file, else 0) on an
 * unparsable entry, NG_E_IO when ban_file cannot be read, NG_E_NOMEM. */
ng_status_t rl_configure(const rl_config_t *cfg, unsigned *bad_line);
void rl_shutdown(void);

bool rl_enabled(rl_class_t c);
/* One unit for key in class c at monotonic time now_ns (rl_allow uses the
 * clock). true = allowed. Always true when the class is unlimited. */
bool rl_allow_at(rl_class_t c, const void *key, size_t len, uint64_t now_ns);
bool rl_allow(rl_class_t c, const void *key, size_t len);

/* The rate-limit key of a peer "ip:port" / "[v6]:port" / bare ip: 4 bytes
 * (IPv4) or the /64 prefix (IPv6). Returns its length, 0 if unparsable. */
size_t rl_peer_key(const char *peer, unsigned char out[16]);

/* The client address of a connection for rate limits and bans. When the
 * TCP peer is a trusted proxy, take the rightmost X-Forwarded-For entry
 * that is not itself a trusted proxy (all of them trusted: the leftmost;
 * an unparsable entry stops the walk at the last good one), else a valid
 * X-Real-IP; otherwise, and when the peer is not trusted, the peer.
 * headers: the raw request header block ("Name: value" lines, may be
 * NULL). Writes the canonical address (no port) or a copy of peer to out;
 * true when a header was used. */
bool rl_client_ip(const char *peer, const char *headers, size_t headers_len, char *out, size_t cap);
bool rl_trusted_proxy(const char *addr);

bool rl_pubkey_banned(const char *hex64);
bool rl_peer_banned(const char *peer);

#endif /* RATELIMIT_H_ */
