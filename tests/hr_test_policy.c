/* ============================================================================
 * Minimal hot-reloadable NIP module for tests/test_hotreload.c.
 *
 * Exports the full 6-function NHR ABI and registers ONE publication
 * policy whose verdict is chosen at COMPILE time:
 *   -DHR_POLICY_ALLOW=1  -> accept_publish returns true
 *   -DHR_POLICY_ALLOW=0  -> accept_publish returns false ("hr-test: deny")
 *   -DHR_ABI_OVERRIDE=N  -> abi_version() reports N instead of
 *                           NHR_ABI_VERSION (negative-path testing)
 *
 * The test builds this file twice with different flags to simulate two
 * module generations and verifies the reloaded generation's policy wins.
 * ============================================================================ */

#include "nhr.h"
#include "nip_capability.h"
#include <stdio.h>
#include <string.h>

#ifndef HR_POLICY_ALLOW
#define HR_POLICY_ALLOW 1
#endif

#ifndef HR_ABI_OVERRIDE
#define HR_ABI_OVERRIDE NHR_ABI_VERSION
#endif

static bool hr_accept_publish(uintptr_t connection_id, const event_t *event,
                              char *reason, size_t reason_size, void *ctx) {
    (void)connection_id;
    (void)event;
    (void)ctx;
#if HR_POLICY_ALLOW
    (void)reason;
    (void)reason_size;
    return true;
#else
    snprintf(reason, reason_size, "hr-test: deny generation");
    return false;
#endif
}

static nip_capability_t hr_caps[] = {
    {
        .name = "hr-test-pub",
        .type = NIP_CAP_PUBLICATION_POLICY,
        .ctx = NULL,
        .caps.publication_policy = { .accept_publish = hr_accept_publish },
        .next = NULL,
    },
};

uint32_t NHR_CALL nhr_module_abi_version(void) {
    return HR_ABI_OVERRIDE;
}

bool NHR_CALL nhr_module_init(const Nhr_Host *host, const relay_config_t *config,
                              void *storage_handle) {
    (void)host;
    (void)config;
    (void)storage_handle;
    return true;
}

void NHR_CALL nhr_module_shutdown(void) {
}

Nhr_State NHR_CALL nhr_module_pre_reload(void) {
    Nhr_State state;
    memset(&state, 0, sizeof(state));
    state.version = NHR_STATE_VERSION;
    return state;
}

bool NHR_CALL nhr_module_post_reload(const Nhr_Host *host,
                                     const relay_config_t *config,
                                     void *storage_handle, Nhr_State state) {
    (void)host;
    (void)config;
    (void)storage_handle;
    (void)state;
    return true;
}

void NHR_CALL nhr_module_register_capabilities(nip_registry_t *host_registry) {
    size_t i;
    if (!host_registry) return;
    for (i = 0; i < sizeof(hr_caps) / sizeof(hr_caps[0]); i++)
        nip_registry_register(host_registry, &hr_caps[i]);
}
