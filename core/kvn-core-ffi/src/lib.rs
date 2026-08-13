//! # kvn-core-ffi
//!
//! Stable C ABI over the pure `kvn-core` control plane, callable from Swift,
//! Kotlin/JNI, Windows and Linux without any Rust-ABI dependency.
//!
//! ## Contract at a glance
//! * **Opaque handle.** Callers hold a `KVNCoreHandle *`; the Rust layout is
//!   never exposed.
//! * **JSON boundary.** Structured calls take a UTF-8, NUL-terminated JSON
//!   request and return a UTF-8 JSON *envelope* through an out-parameter, plus
//!   a stable `int32_t` status code. Request and envelope both carry
//!   `schema_version`.
//! * **No panics cross the boundary.** Every `extern "C"` function wraps its
//!   body in [`std::panic::catch_unwind`]; a panic becomes `KVN_CORE_PANIC`.
//! * **No secrets.** The core accepts none, and the wire DTOs have no field to
//!   carry one; see [`dto`].
//! * **Thread-safe handle.** Each handle serializes access with an internal
//!   mutex. See the threading notes on [`KVNCoreHandle`].
//!
//! All `unsafe` in the project is confined to this crate.

#![allow(clippy::missing_safety_doc)] // Safety is documented in kvn_core.h and per-function.

mod dto;

use kvn_core::error::CoreError;
use kvn_core::model::{CandidateId, ProfileId};
use kvn_core::KvnCore;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Versioning
// ---------------------------------------------------------------------------

/// ABI version. Bumped only on a breaking change to the C symbol contract.
pub const KVN_CORE_ABI_VERSION: u32 = 1;

/// NUL-terminated static crate version, returned by [`kvn_core_version`].
const VERSION_CSTR: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");

// ---------------------------------------------------------------------------
// Stable error codes (explicit values; never derived from Rust enum layout)
// ---------------------------------------------------------------------------

pub const KVN_CORE_OK: i32 = 0;
pub const KVN_CORE_INVALID_ARGUMENT: i32 = 1;
pub const KVN_CORE_INVALID_HANDLE: i32 = 2;
pub const KVN_CORE_INVALID_UTF8: i32 = 3;
pub const KVN_CORE_INVALID_JSON: i32 = 4;
pub const KVN_CORE_SCHEMA_MISMATCH: i32 = 5;
pub const KVN_CORE_NOT_FOUND: i32 = 6;
pub const KVN_CORE_INVALID_STATE: i32 = 7;
pub const KVN_CORE_INTERNAL_ERROR: i32 = 8;
pub const KVN_CORE_PANIC: i32 = 9;

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// Opaque handle owning one [`KvnCore`] instance and its last-error slot.
///
/// Threading model: the handle is `Send + Sync`; every ABI call takes the
/// internal mutex, so concurrent calls on the same handle are *safe* but
/// *serialized*. Independent handles share nothing. A panic that poisons the
/// mutex is recovered (the guard is taken via `into_inner`) so one bad call
/// cannot permanently brick a handle.
pub struct KVNCoreHandle {
    core: Mutex<KvnCore>,
    last_error: Mutex<Option<String>>,
}

impl KVNCoreHandle {
    fn lock_core(&self) -> std::sync::MutexGuard<'_, KvnCore> {
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_last_error(&self, message: Option<String>) {
        if let Ok(mut slot) = self.last_error.lock() {
            *slot = message;
        }
    }
}

// ---------------------------------------------------------------------------
// Boundary error type
// ---------------------------------------------------------------------------

struct ApiError {
    code: i32,
    tag: &'static str,
    message: String,
}

impl ApiError {
    fn new(code: i32, tag: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            tag,
            message: message.into(),
        }
    }

    /// Shape/parse failure while decoding a request body. The serde detail is
    /// intentionally dropped to avoid leaking anything into the response.
    fn bad_request() -> Self {
        Self::new(
            KVN_CORE_INVALID_JSON,
            "INVALID_JSON",
            "request JSON did not match the expected shape",
        )
    }
}

impl From<CoreError> for ApiError {
    fn from(err: CoreError) -> Self {
        // CoreError messages are already sanitized (only opaque ids/categories).
        let (code, tag) = match &err {
            CoreError::UnknownCandidate(_) => (KVN_CORE_NOT_FOUND, "NOT_FOUND"),
            CoreError::InvalidStateTransition { .. } => (KVN_CORE_INVALID_STATE, "INVALID_STATE"),
            CoreError::InvalidConfiguration(_)
            | CoreError::InvalidInput(_)
            | CoreError::DuplicateCandidate(_) => (KVN_CORE_INVALID_ARGUMENT, "INVALID_ARGUMENT"),
            CoreError::NoHealthyCandidates => (KVN_CORE_INVALID_STATE, "INVALID_STATE"),
            CoreError::Serialization(_) => (KVN_CORE_INTERNAL_ERROR, "INTERNAL_ERROR"),
        };
        Self::new(code, tag, err.to_string())
    }
}

type ApiResult = Result<Value, ApiError>;

// ---------------------------------------------------------------------------
// Envelope helpers
// ---------------------------------------------------------------------------

fn ok_envelope(data: Value) -> String {
    json!({
        "schema_version": kvn_core::SCHEMA_VERSION,
        "ok": true,
        "data": data,
    })
    .to_string()
}

fn err_envelope(tag: &str, message: &str) -> String {
    json!({
        "schema_version": kvn_core::SCHEMA_VERSION,
        "ok": false,
        "error": { "code": tag, "message": message },
    })
    .to_string()
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(|_| ApiError::bad_request())
}

// ---------------------------------------------------------------------------
// Core dispatch: shared validation + panic containment for JSON functions
// ---------------------------------------------------------------------------

/// Runs a JSON operation with full boundary hardening. Returns a stable status
/// code and always writes an owned envelope string to `*out_response` (unless
/// `out_response` itself is null). The written string must be released with
/// [`kvn_core_free_string`].
unsafe fn json_call<F>(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
    op: F,
) -> i32
where
    F: FnOnce(&mut KvnCore, Value) -> ApiResult,
{
    // Without an out-pointer we cannot return a body; fail fast, touch nothing.
    if out_response.is_null() {
        return KVN_CORE_INVALID_ARGUMENT;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let Some(handle_ref) = handle.as_ref() else {
            return (
                KVN_CORE_INVALID_HANDLE,
                err_envelope("INVALID_HANDLE", "handle pointer was null"),
                None,
            );
        };

        if request_json.is_null() {
            return (
                KVN_CORE_INVALID_ARGUMENT,
                err_envelope("INVALID_ARGUMENT", "request pointer was null"),
                None,
            );
        }

        let text = match CStr::from_ptr(request_json).to_str() {
            Ok(t) => t,
            Err(_) => {
                return (
                    KVN_CORE_INVALID_UTF8,
                    err_envelope("INVALID_UTF8", "request was not valid UTF-8"),
                    None,
                )
            }
        };

        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => {
                return (
                    KVN_CORE_INVALID_JSON,
                    err_envelope("INVALID_JSON", "request was not valid JSON"),
                    None,
                )
            }
        };

        match value.get("schema_version").and_then(Value::as_u64) {
            Some(v) if v as u32 == kvn_core::SCHEMA_VERSION => {}
            _ => {
                return (
                    KVN_CORE_SCHEMA_MISMATCH,
                    err_envelope("SCHEMA_MISMATCH", "missing or unsupported schema_version"),
                    None,
                )
            }
        }

        // Hold the core lock only for the operation itself; serialize the
        // response after releasing it.
        let result = {
            let mut core = handle_ref.lock_core();
            op(&mut core, value)
        };

        match result {
            Ok(data) => (KVN_CORE_OK, ok_envelope(data), None),
            Err(e) => (e.code, err_envelope(e.tag, &e.message), Some(e.message)),
        }
    }));

    let (code, body, last_error) = match outcome {
        Ok(triple) => triple,
        Err(_) => (
            KVN_CORE_PANIC,
            err_envelope("PANIC", "a panic was caught at the FFI boundary"),
            Some("panic".to_string()),
        ),
    };

    // Record per-handle last error (best effort; ignore if handle was null).
    if let Some(handle_ref) = handle.as_ref() {
        handle_ref.set_last_error(last_error);
    }

    match CString::new(body) {
        Ok(cs) => {
            *out_response = cs.into_raw();
            code
        }
        Err(_) => {
            *out_response = ptr::null_mut();
            KVN_CORE_INTERNAL_ERROR
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Creates a new core handle. Returns null only on allocation failure/panic.
/// Ownership transfers to the caller; release with [`kvn_core_destroy`].
#[no_mangle]
pub extern "C" fn kvn_core_create() -> *mut KVNCoreHandle {
    catch_unwind(|| {
        Box::into_raw(Box::new(KVNCoreHandle {
            core: Mutex::new(KvnCore::default()),
            last_error: Mutex::new(None),
        }))
    })
    .unwrap_or(ptr::null_mut())
}

/// Destroys a handle. Passing null is a safe no-op. After this call the pointer
/// is dangling and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn kvn_core_destroy(handle: *mut KVNCoreHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(Box::from_raw(handle));
    }));
}

// ---------------------------------------------------------------------------
// Versioning (static / scalar — nothing to free)
// ---------------------------------------------------------------------------

/// Returns a pointer to a static NUL-terminated version string. Do NOT free it.
#[no_mangle]
pub extern "C" fn kvn_core_version() -> *const c_char {
    VERSION_CSTR.as_ptr() as *const c_char
}

/// Returns the stable ABI version.
#[no_mangle]
pub extern "C" fn kvn_core_abi_version() -> u32 {
    KVN_CORE_ABI_VERSION
}

/// Returns the JSON schema version used on the boundary.
#[no_mangle]
pub extern "C" fn kvn_core_schema_version() -> u32 {
    kvn_core::SCHEMA_VERSION
}

// ---------------------------------------------------------------------------
// Memory / error accessors
// ---------------------------------------------------------------------------

/// Frees a string previously returned by this library (envelope responses,
/// `kvn_core_last_error`). Passing null is a safe no-op. Never call libc/Swift
/// `free` on these pointers, and never free the same pointer twice.
#[no_mangle]
pub unsafe extern "C" fn kvn_core_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(CString::from_raw(ptr));
    }));
}

/// Returns the most recent error message for this handle as an owned string
/// (free with [`kvn_core_free_string`]), or null if there is none / handle is
/// null. The message is sanitized (no secrets).
#[no_mangle]
pub unsafe extern "C" fn kvn_core_last_error(handle: *mut KVNCoreHandle) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle_ref = handle.as_ref()?;
        let message = handle_ref.last_error.lock().ok()?.clone()?;
        CString::new(message).ok().map(CString::into_raw)
    }));
    result.ok().flatten().unwrap_or(ptr::null_mut())
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kvn_core_set_configuration(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::SetConfigurationRequest = decode(value)?;
        core.set_configuration(req.config)?;
        Ok(json!({}))
    })
}

// ---------------------------------------------------------------------------
// Candidate lifecycle
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kvn_core_register_candidate(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::RegisterCandidateRequest = decode(value)?;
        core.register_candidate(
            CandidateId::new(req.candidate_id),
            ProfileId::new(req.profile_id),
            req.endpoint,
        )?;
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_remove_candidate(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::CandidateIdRequest = decode(value)?;
        core.remove_candidate(&CandidateId::new(req.candidate_id))?;
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_update_candidate(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::UpdateCandidateRequest = decode(value)?;
        core.update_candidate(&CandidateId::new(req.candidate_id), req.endpoint)?;
        Ok(json!({}))
    })
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kvn_core_update_health(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::UpdateHealthRequest = decode(value)?;
        core.update_health(&CandidateId::new(req.candidate_id), req.sample)?;
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_set_network_type(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::SetNetworkTypeRequest = decode(value)?;
        core.set_network_type(req.network_type);
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_set_current_candidate(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::SetCurrentCandidateRequest = decode(value)?;
        let id = req.candidate_id.map(CandidateId::new);
        core.set_current_candidate(id, req.now_ms)?;
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_report_success(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::CandidateReportRequest = decode(value)?;
        core.report_connection_success(&CandidateId::new(req.candidate_id), req.now_ms)?;
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_report_failure(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::CandidateReportRequest = decode(value)?;
        core.report_connection_failure(&CandidateId::new(req.candidate_id), req.now_ms)?;
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_set_traffic_counters(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::SetTrafficCountersRequest = decode(value)?;
        core.set_traffic_counters(req.bytes_sent, req.bytes_received);
        Ok(json!({}))
    })
}

// ---------------------------------------------------------------------------
// Decisions / queries
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn kvn_core_select_best(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::NowRequest = decode(value)?;
        let decision = core.select_best(req.now_ms);
        serde_json::to_value(decision)
            .map_err(|_| ApiError::new(KVN_CORE_INTERNAL_ERROR, "INTERNAL_ERROR", "encode"))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_get_state(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, _value| {
        Ok(json!({ "state": core.get_state() }))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_handle_event(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::HandleEventRequest = decode(value)?;
        let state = core.handle_event(req.event, req.now_ms)?;
        Ok(json!({ "state": state }))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_get_statistics(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::NowRequest = decode(value)?;
        let stats = core.get_statistics(req.now_ms);
        serde_json::to_value(stats)
            .map_err(|_| ApiError::new(KVN_CORE_INTERNAL_ERROR, "INTERNAL_ERROR", "encode"))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_set_routing_rules(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::SetRoutingRulesRequest = decode(value)?;
        core.set_routing_rules(req.rules);
        Ok(json!({}))
    })
}

#[no_mangle]
pub unsafe extern "C" fn kvn_core_resolve_route(
    handle: *mut KVNCoreHandle,
    request_json: *const c_char,
    out_response: *mut *mut c_char,
) -> i32 {
    json_call(handle, request_json, out_response, |core, value| {
        let req: dto::ResolveRouteRequest = decode(value)?;
        let action = core.resolve_route(&req.query);
        Ok(json!({ "action": action }))
    })
}

// ---------------------------------------------------------------------------
// Panic-boundary self-test (used by FFI tests; harmless in production)
// ---------------------------------------------------------------------------

/// Deliberately panics inside the boundary guard to prove a panic never
/// unwinds into the caller. Always returns [`KVN_CORE_PANIC`].
///
/// This symbol is compiled ONLY under `cfg(test)` or the non-default
/// `ffi-test-hooks` feature, so it never appears in shipped release artifacts.
#[cfg(any(test, feature = "ffi-test-hooks"))]
#[no_mangle]
pub extern "C" fn kvn_core_debug_force_panic() -> i32 {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        panic!("intentional panic for FFI boundary verification");
    }));
    match outcome {
        Ok(()) => KVN_CORE_OK,
        Err(_) => KVN_CORE_PANIC,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Panic-boundary containment: verified as a unit test so it works via
    // cfg(test) without exposing the hook in production builds.
    #[test]
    fn panic_is_contained_at_boundary() {
        assert_eq!(kvn_core_debug_force_panic(), KVN_CORE_PANIC);
    }
}
