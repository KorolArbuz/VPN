/*
 * kvn_core.h — Stable C ABI for the KVN control-plane core.
 *
 * Portable across Apple (Swift/Obj-C), Android (NDK/JNI), Windows and Linux.
 * No platform-specific includes. C99 or later.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * OVERVIEW
 * ─────────────────────────────────────────────────────────────────────────
 * The control-plane engine decides *which* candidate to connect to and *when*
 * to switch. It performs no I/O, holds no secrets, and never launches a
 * backend. Structured calls exchange UTF-8 JSON:
 *
 *   - Every request is a UTF-8, NUL-terminated JSON object containing an
 *     integer  "schema_version"  field.
 *   - Every structured call returns a stable int32_t status code AND writes an
 *     owned UTF-8 JSON *envelope* to its out-parameter:
 *
 *         { "schema_version": 1, "ok": true,  "data": { ... } }
 *         { "schema_version": 1, "ok": false, "error": { "code": "...",
 *                                                        "message": "..." } }
 *
 *     The status code and envelope "ok" always agree. On success the caller
 *     reads "data"; on failure, "error".
 *
 * ─────────────────────────────────────────────────────────────────────────
 * MEMORY / OWNERSHIP
 * ─────────────────────────────────────────────────────────────────────────
 *   - KVNCoreHandle* is created by kvn_core_create() and owned by the caller
 *     until kvn_core_destroy(). After destroy the pointer is dangling.
 *   - Any char* written to an out-parameter, and any char* returned by
 *     kvn_core_last_error(), is heap-allocated by this library and owned by the
 *     caller. Release it EXACTLY once with kvn_core_free_string().
 *     Never use libc/Swift free() on it. Never free it twice.
 *   - kvn_core_version() returns a pointer to a STATIC string — do NOT free it.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * THREAD SAFETY
 * ─────────────────────────────────────────────────────────────────────────
 *   - A handle is safe to call from multiple threads; calls on the same handle
 *     are serialized by an internal mutex (no external locking required).
 *   - Distinct handles are fully independent and share no state (including
 *     last-error state).
 *   - kvn_core_destroy() must not race with other calls on the same handle;
 *     ensure no in-flight call is using the handle when you destroy it.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * SAFETY / ROBUSTNESS
 * ─────────────────────────────────────────────────────────────────────────
 *   - All string inputs must be valid UTF-8; invalid UTF-8 yields
 *     KVN_CORE_INVALID_UTF8 (never a crash).
 *   - A NULL handle yields KVN_CORE_INVALID_HANDLE; a NULL request yields
 *     KVN_CORE_INVALID_ARGUMENT. A NULL out-parameter yields
 *     KVN_CORE_INVALID_ARGUMENT and nothing is written.
 *   - No Rust panic ever crosses this boundary; a caught panic becomes
 *     KVN_CORE_PANIC.
 *   - No secret material (UUIDs, passwords, keys, tokens, URIs, subscription
 *     URLs) is ever accepted or emitted.
 */

#ifndef KVN_CORE_H
#define KVN_CORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle. The Rust layout is never exposed. */
typedef struct KVNCoreHandle KVNCoreHandle;

/* ---- Stable status codes (explicit values) ---------------------------- */
#define KVN_CORE_OK                0
#define KVN_CORE_INVALID_ARGUMENT  1
#define KVN_CORE_INVALID_HANDLE    2
#define KVN_CORE_INVALID_UTF8      3
#define KVN_CORE_INVALID_JSON      4
#define KVN_CORE_SCHEMA_MISMATCH   5
#define KVN_CORE_NOT_FOUND         6
#define KVN_CORE_INVALID_STATE     7
#define KVN_CORE_INTERNAL_ERROR    8
#define KVN_CORE_PANIC             9

/* ---- Lifecycle -------------------------------------------------------- */

/* Create a handle. Returns NULL only on allocation failure.
 * Ownership transfers to the caller; release with kvn_core_destroy(). */
KVNCoreHandle *kvn_core_create(void);

/* Destroy a handle. Passing NULL is a safe no-op. */
void kvn_core_destroy(KVNCoreHandle *handle);

/* ---- Versioning ------------------------------------------------------- */

/* Static NUL-terminated semantic version string. Do NOT free. */
const char *kvn_core_version(void);

/* Stable ABI version (bumped only on breaking C-contract changes). */
uint32_t kvn_core_abi_version(void);

/* JSON schema version used on this boundary. */
uint32_t kvn_core_schema_version(void);

/* ---- Memory / error --------------------------------------------------- */

/* Free a string produced by this library. NULL is a safe no-op.
 * Do not call more than once per pointer. */
void kvn_core_free_string(char *ptr);

/* Most recent sanitized error message for this handle as an owned string
 * (free with kvn_core_free_string), or NULL if none / handle is NULL. */
char *kvn_core_last_error(KVNCoreHandle *handle);

/* ---- Structured JSON operations --------------------------------------
 *
 * All functions below share the signature:
 *
 *   int32_t fn(KVNCoreHandle *handle,
 *              const char *request_json,      // UTF-8, NUL-terminated
 *              char **out_response);          // receives owned JSON envelope
 *
 * They return a KVN_CORE_* status code and, unless out_response is NULL,
 * write an owned envelope string to *out_response (free with
 * kvn_core_free_string).
 */

int32_t kvn_core_set_configuration(KVNCoreHandle *handle, const char *request_json, char **out_response);

int32_t kvn_core_register_candidate(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_remove_candidate(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_update_candidate(KVNCoreHandle *handle, const char *request_json, char **out_response);

int32_t kvn_core_update_health(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_set_network_type(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_set_current_candidate(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_report_success(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_report_failure(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_set_traffic_counters(KVNCoreHandle *handle, const char *request_json, char **out_response);

int32_t kvn_core_select_best(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_get_state(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_handle_event(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_get_statistics(KVNCoreHandle *handle, const char *request_json, char **out_response);

int32_t kvn_core_set_routing_rules(KVNCoreHandle *handle, const char *request_json, char **out_response);
int32_t kvn_core_resolve_route(KVNCoreHandle *handle, const char *request_json, char **out_response);

/* ---- Diagnostics ------------------------------------------------------ */

/* Deliberately triggers and catches a panic at the boundary; always returns
 * KVN_CORE_PANIC. For verifying panic containment. Never affects state. */
int32_t kvn_core_debug_force_panic(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KVN_CORE_H */
