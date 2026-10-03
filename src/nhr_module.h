#ifndef NHR_MODULE_H_
#define NHR_MODULE_H_

#include "nhr.h"

#define NHR_DECLARE_MODULE_FUNCTION(ret, name, args) \
    ret NHR_CALL nhr_module_##name args;
NHR_MODULE_FUNCTIONS(NHR_DECLARE_MODULE_FUNCTION)
#undef NHR_DECLARE_MODULE_FUNCTION

/* No extra ABI declarations: all module exports are declared by
 * NHR_MODULE_FUNCTIONS above. */

/* Host-session shims (implemented in nhr_module.c, module builds only).
 * Forward NIP session-auth state to the host-owned connection_session list
 * so it survives reload. Borrowed strings follow the Nhr_Host lifetime
 * rule: valid until the next session mutation, copy if retained. */
const char *nhr_module_session_challenge(uintptr_t connection_id);
bool nhr_module_session_set_challenge(uintptr_t connection_id,
                                      const char *challenge);
const char *nhr_module_session_auth_pubkey(uintptr_t connection_id);
bool nhr_module_session_set_auth(uintptr_t connection_id, const char *pubkey);
void nhr_module_session_clear_auth(uintptr_t connection_id);
bool nhr_module_session_add_auth(uintptr_t connection_id, const char *pubkey);
bool nhr_module_session_has_auth(uintptr_t connection_id, const char *pubkey);
size_t nhr_module_session_auth_count(uintptr_t connection_id);
const char *nhr_module_session_auth_at(uintptr_t connection_id, size_t index);
size_t nhr_module_session_snapshot(connection_snapshot_t *out, size_t capacity);
bool nhr_module_send_json(uintptr_t connection_id, const char *json, size_t length);
/* Full event validation bridge (ID + signature + NIP-26 delegation,
 * mirroring host check_event()). Plain internal function, not an ABI export. */
bool nhr_module_accepts_event(const event_t *event);
/* Count leading zero bits (for NIP-13 PoW). */
unsigned nhr_module_count_leading_zero_bits(const char *hex);

#endif /* NHR_MODULE_H_ */
