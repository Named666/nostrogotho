/* relay_wire - pure helpers that look at a raw (still unparsed) Nostr client
 * message. They run before the full JSON parse, on paths where a full parse
 * would be wasted work: inline load shedding on the I/O thread and batch
 * signature pre-verification on the workers.
 *
 * Contract: no allocation, no globals, no I/O; thread-safe. Input is the
 * raw message (not necessarily NUL-terminated); nothing is retained.
 * Malformed input never fails hard: the helpers report "not recognized"
 * and the normal parser later produces the protocol error.
 */
#ifndef RELAY_WIRE_H_
#define RELAY_WIRE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Room for the longest reply relay_wire_overload_reply produces with a
 * reason of up to 100 bytes. */
#define RELAY_WIRE_REPLY_MAX 320

/* Build the refusal for a message the relay will not process, without
 * parsing more than its first two array elements:
 *   ["EVENT",{..."id":"<64 hex>"...}]   -> ["OK","<id>",false,"<why>"]
 *   ["REQ"|"COUNT","<plain sub id>",...] -> ["CLOSED","<sub>","<why>"]
 *   anything else                        -> ["NOTICE","<why>"]
 * why must be JSON-safe (no '"' or '\\'). Writes at most cap bytes to out
 * (no NUL) and returns the length, or 0 if even the NOTICE does not fit. */
size_t relay_wire_overload_reply(const char *msg, size_t len, const char *why,
                                 char *out, size_t cap);

/* The (id, pubkey, sig) of a raw ["EVENT",{...}] message, hex-decoded.
 * true only if the message is an EVENT whose object has all three fields
 * as lowercase/uppercase hex strings of the right length; outputs are
 * written only on success. Leading whitespace is skipped. */
bool relay_wire_event_sig(const char *msg, size_t len,
                          uint8_t id[32], uint8_t pubkey[32], uint8_t sig[64]);

#endif /* RELAY_WIRE_H_ */
