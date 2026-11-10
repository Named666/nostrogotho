#ifndef WS_PROTO_H_
#define WS_PROTO_H_
/* Minimal RFC 6455 helpers (in-tree, MIT): SHA-1, base64, accept key,
 * frame header encode and incremental frame parse.
 *
 * Contract: pure functions, no allocation, no globals, thread-safe. Buffers
 * are caller-owned with the sizes stated per function. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ng_status.h"

void ws_sha1(const unsigned char *data, size_t len, unsigned char out[20]);
size_t ws_base64(const unsigned char *in, size_t len, char *out); /* NUL-terminates */
/* out must hold 29 bytes. */
void ws_accept_key(const char *client_key, size_t key_len, char out[29]);

enum { WS_OP_CONT = 0, WS_OP_TEXT = 1, WS_OP_BIN = 2, WS_OP_CLOSE = 8, WS_OP_PING = 9, WS_OP_PONG = 10 };

/* Server->client header (unmasked). Returns header length (2..10). */
size_t ws_frame_header(unsigned char *hdr, int opcode, size_t payload_len);

typedef struct {
    bool fin;
    int opcode;
    bool masked;
    uint64_t len;
    size_t header_len;
    unsigned char mask[4];
} ws_frame_t;

/* Parse a frame header from buf[0..n).
 *   NG_OK        complete header; f filled
 *   NG_E_AGAIN   more bytes needed
 *   NG_E_INVALID protocol error (RSV bits, reserved opcode, control frame
 *                over 125 bytes or fragmented, 64-bit length MSB set)
 * f is fully written only on NG_OK. */
ng_status_t ws_parse_header(const unsigned char *buf, size_t n, ws_frame_t *f);
#include <stdbool.h>
bool ws_utf8_valid(const unsigned char *s, size_t n);
void ws_unmask(unsigned char *p, size_t n, const unsigned char mask[4]);
#endif
