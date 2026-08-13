//! C ABI boundary tests. Everything here exercises the exported `extern "C"`
//! surface exactly as a C/Swift caller would: build NUL-terminated UTF-8
//! requests, read owned envelopes, and release them with `kvn_core_free_string`.

use kvn_core_ffi::*;
use serde_json::Value;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

type JsonFn = unsafe extern "C" fn(*mut KVNCoreHandle, *const c_char, *mut *mut c_char) -> i32;

/// Calls a JSON function and returns `(status_code, envelope_json_string)`,
/// freeing the returned string with the library allocator.
unsafe fn call(f: JsonFn, handle: *mut KVNCoreHandle, request: &str) -> (i32, String) {
    let creq = CString::new(request).unwrap();
    let mut out: *mut c_char = ptr::null_mut();
    let code = f(handle, creq.as_ptr(), &mut out);
    let body = if out.is_null() {
        String::new()
    } else {
        let s = CStr::from_ptr(out).to_string_lossy().into_owned();
        kvn_core_free_string(out);
        s
    };
    (code, body)
}

fn envelope(body: &str) -> Value {
    serde_json::from_str(body).expect("envelope is valid JSON")
}

const REGISTER_A: &str = r#"{"schema_version":1,"candidate_id":"a","profile_id":"p","endpoint":{"host":"a.example.com","port":443,"protocol":"vless","backend":"xray"}}"#;
const HEALTH_A: &str = r#"{"schema_version":1,"candidate_id":"a","sample":{"timestamp_ms":100,"reachable":true,"latency_ms":40.0,"packet_loss_percent":0.0}}"#;
const SELECT: &str = r#"{"schema_version":1,"now_ms":100}"#;

// 1 & 2: create returns a valid handle; destroy is clean.
#[test]
fn create_and_destroy() {
    unsafe {
        let h = kvn_core_create();
        assert!(!h.is_null());
        kvn_core_destroy(h);
    }
}

// 3: destroying NULL is a safe no-op.
#[test]
fn destroy_null_is_safe() {
    unsafe { kvn_core_destroy(ptr::null_mut()) }
}

// 4: a NULL handle on a structured call returns INVALID_HANDLE, no crash.
#[test]
fn null_handle_does_not_crash() {
    unsafe {
        let (code, body) = call(kvn_core_register_candidate, ptr::null_mut(), REGISTER_A);
        assert_eq!(code, KVN_CORE_INVALID_HANDLE);
        assert_eq!(envelope(&body)["ok"], Value::Bool(false));
    }
}

// 5: valid candidate JSON registers.
#[test]
fn register_valid_candidate() {
    unsafe {
        let h = kvn_core_create();
        let (code, body) = call(kvn_core_register_candidate, h, REGISTER_A);
        assert_eq!(code, KVN_CORE_OK, "{body}");
        assert_eq!(envelope(&body)["ok"], Value::Bool(true));
        kvn_core_destroy(h);
    }
}

// 6: malformed JSON returns INVALID_JSON.
#[test]
fn malformed_json_is_rejected() {
    unsafe {
        let h = kvn_core_create();
        let (code, body) = call(kvn_core_register_candidate, h, "{not valid json");
        assert_eq!(code, KVN_CORE_INVALID_JSON);
        assert_eq!(envelope(&body)["error"]["code"], "INVALID_JSON");
        kvn_core_destroy(h);
    }
}

// 7: invalid UTF-8 input returns INVALID_UTF8.
#[test]
fn invalid_utf8_is_rejected() {
    unsafe {
        let h = kvn_core_create();
        // 0xFF is not valid UTF-8; CString only forbids interior NUL.
        let bad = CString::new(vec![0xFFu8, 0xFE, 0x41]).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let code = kvn_core_register_candidate(h, bad.as_ptr(), &mut out);
        assert_eq!(code, KVN_CORE_INVALID_UTF8);
        assert!(!out.is_null());
        kvn_core_free_string(out);
        kvn_core_destroy(h);
    }
}

// 8: wrong schema version returns SCHEMA_MISMATCH.
#[test]
fn wrong_schema_version_is_rejected() {
    unsafe {
        let h = kvn_core_create();
        let req = r#"{"schema_version":999,"candidate_id":"a","profile_id":"p","endpoint":{"host":"h","port":443,"protocol":"vless","backend":"xray"}}"#;
        let (code, body) = call(kvn_core_register_candidate, h, req);
        assert_eq!(code, KVN_CORE_SCHEMA_MISMATCH);
        assert_eq!(envelope(&body)["error"]["code"], "SCHEMA_MISMATCH");
        kvn_core_destroy(h);
    }
}

// 9: unknown candidate returns NOT_FOUND.
#[test]
fn unknown_candidate_is_not_found() {
    unsafe {
        let h = kvn_core_create();
        let req = r#"{"schema_version":1,"candidate_id":"ghost"}"#;
        let (code, body) = call(kvn_core_remove_candidate, h, req);
        assert_eq!(code, KVN_CORE_NOT_FOUND);
        assert_eq!(envelope(&body)["error"]["code"], "NOT_FOUND");
        kvn_core_destroy(h);
    }
}

// 10: selection response decodes correctly.
#[test]
fn selection_response_decodes() {
    unsafe {
        let h = kvn_core_create();
        call(kvn_core_register_candidate, h, REGISTER_A);
        call(kvn_core_update_health, h, HEALTH_A);
        let (code, body) = call(kvn_core_select_best, h, SELECT);
        assert_eq!(code, KVN_CORE_OK, "{body}");
        let env = envelope(&body);
        assert_eq!(env["ok"], Value::Bool(true));
        assert_eq!(env["data"]["selected"], "a");
        assert_eq!(env["data"]["reason"], "initial_selection");
        assert!(env["data"]["breakdown"]["total"].is_number());
        kvn_core_destroy(h);
    }
}

// 11: statistics response decodes correctly.
#[test]
fn statistics_response_decodes() {
    unsafe {
        let h = kvn_core_create();
        call(kvn_core_register_candidate, h, REGISTER_A);
        call(kvn_core_update_health, h, HEALTH_A);
        call(
            kvn_core_set_current_candidate,
            h,
            r#"{"schema_version":1,"candidate_id":"a","now_ms":100}"#,
        );
        let (code, body) = call(
            kvn_core_get_statistics,
            h,
            r#"{"schema_version":1,"now_ms":200}"#,
        );
        assert_eq!(code, KVN_CORE_OK, "{body}");
        let env = envelope(&body);
        assert_eq!(env["data"]["current_candidate"], "a");
        assert_eq!(env["data"]["total_switches"], 1);
        assert!(env["data"]["network_type"].is_string());
        kvn_core_destroy(h);
    }
}

// 12: route response decodes correctly.
#[test]
fn route_response_decodes() {
    unsafe {
        let h = kvn_core_create();
        let rules = r#"{"schema_version":1,"rules":[{"matcher":{"kind":"exact_domain","value":"example.com"},"action":"direct","priority":1},{"matcher":{"kind":"catch_all"},"action":"vpn","priority":100}]}"#;
        let (code, _) = call(kvn_core_set_routing_rules, h, rules);
        assert_eq!(code, KVN_CORE_OK);

        let (code, body) = call(
            kvn_core_resolve_route,
            h,
            r#"{"schema_version":1,"query":{"domain":"example.com"}}"#,
        );
        assert_eq!(code, KVN_CORE_OK);
        assert_eq!(envelope(&body)["data"]["action"], "direct");

        let (_, body) = call(
            kvn_core_resolve_route,
            h,
            r#"{"schema_version":1,"query":{"domain":"other.org"}}"#,
        );
        assert_eq!(envelope(&body)["data"]["action"], "vpn");
        kvn_core_destroy(h);
    }
}

// 13 & 14 (panic containment) live as a cfg(test) unit test inside the crate,
// because the panic hook symbol is gated out of production builds. See
// `kvn_core_ffi::tests::panic_is_contained_at_boundary`.

// 15: strings can be freed with kvn_core_free_string (and double-free is not
//     encouraged — we free exactly once, plus NULL is a no-op).
#[test]
fn free_string_contract() {
    unsafe {
        let h = kvn_core_create();
        let creq = CString::new(REGISTER_A).unwrap();
        let mut out: *mut c_char = ptr::null_mut();
        let code = kvn_core_register_candidate(h, creq.as_ptr(), &mut out);
        assert_eq!(code, KVN_CORE_OK);
        assert!(!out.is_null(), "a response string must be allocated");
        kvn_core_free_string(out);
        kvn_core_free_string(ptr::null_mut()); // no-op
        kvn_core_destroy(h);
    }
}

// 16: repeated create/destroy cycles work.
#[test]
fn repeated_create_destroy_cycles() {
    unsafe {
        for _ in 0..200 {
            let h = kvn_core_create();
            assert!(!h.is_null());
            call(kvn_core_register_candidate, h, REGISTER_A);
            kvn_core_destroy(h);
        }
    }
}

// 17: two independent handles keep independent state.
#[test]
fn handles_are_independent() {
    unsafe {
        let h1 = kvn_core_create();
        let h2 = kvn_core_create();
        call(kvn_core_register_candidate, h1, REGISTER_A);
        call(kvn_core_update_health, h1, HEALTH_A);

        let (_, b1) = call(kvn_core_select_best, h1, SELECT);
        let (_, b2) = call(kvn_core_select_best, h2, SELECT);
        assert_eq!(envelope(&b1)["data"]["selected"], "a");
        assert_eq!(envelope(&b2)["data"]["reason"], "no_healthy_candidates");
        kvn_core_destroy(h1);
        kvn_core_destroy(h2);
    }
}

// 18: an error on one handle does not contaminate another's last-error.
#[test]
fn errors_do_not_leak_across_handles() {
    unsafe {
        let h1 = kvn_core_create();
        let h2 = kvn_core_create();
        // Trigger an error on h1 only.
        call(
            kvn_core_remove_candidate,
            h1,
            r#"{"schema_version":1,"candidate_id":"ghost"}"#,
        );

        let e1 = kvn_core_last_error(h1);
        let e2 = kvn_core_last_error(h2);
        assert!(!e1.is_null(), "h1 should have a last error");
        assert!(e2.is_null(), "h2 must be unaffected");
        kvn_core_free_string(e1);
        kvn_core_destroy(h1);
        kvn_core_destroy(h2);
    }
}

// 19: concurrent calls on one shared handle are safe (serialized internally).
#[test]
fn concurrent_calls_are_safe() {
    unsafe {
        let h = kvn_core_create();
        let addr = h as usize; // usize is Send; the handle serializes internally.
        let mut threads = Vec::new();
        for t in 0..8 {
            threads.push(std::thread::spawn(move || {
                let h = addr as *mut KVNCoreHandle;
                let req = format!(
                    r#"{{"schema_version":1,"candidate_id":"c{t}","profile_id":"p","endpoint":{{"host":"h","port":443,"protocol":"vless","backend":"xray"}}}}"#
                );
                let (code, _) = call(kvn_core_register_candidate, h, &req);
                assert_eq!(code, KVN_CORE_OK);
                let health = format!(
                    r#"{{"schema_version":1,"candidate_id":"c{t}","sample":{{"timestamp_ms":1,"reachable":true,"latency_ms":30.0}}}}"#
                );
                call(kvn_core_update_health, h, &health);
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        // All eight distinct candidates registered; one is selectable.
        let (code, body) = call(kvn_core_select_best, h, SELECT);
        assert_eq!(code, KVN_CORE_OK);
        assert!(envelope(&body)["data"]["selected"].is_string());
        kvn_core_destroy(h);
    }
}

// 20: no serialized ABI output ever contains credential-like markers, even
//     when a request smuggles an extra "password" field (it has nowhere to
//     land in the core and is dropped).
#[test]
fn serialized_output_has_no_secrets() {
    unsafe {
        let h = kvn_core_create();
        let sneaky = r#"{"schema_version":1,"candidate_id":"a","profile_id":"p","password":"hunter2","uuid":"11111111-2222-3333-4444-555555555555","endpoint":{"host":"a.example.com","port":443,"protocol":"vless","backend":"xray","private_key":"leakme"}}"#;
        let (code, reg) = call(kvn_core_register_candidate, h, sneaky);
        assert_eq!(code, KVN_CORE_OK, "{reg}");
        call(kvn_core_update_health, h, HEALTH_A);
        call(
            kvn_core_set_current_candidate,
            h,
            r#"{"schema_version":1,"candidate_id":"a","now_ms":100}"#,
        );

        let (_, sel) = call(kvn_core_select_best, h, SELECT);
        let (_, stats) = call(
            kvn_core_get_statistics,
            h,
            r#"{"schema_version":1,"now_ms":100}"#,
        );

        const FORBIDDEN: &[&str] = &[
            "hunter2",
            "leakme",
            "password",
            "private_key",
            "uuid",
            "token",
            "secret",
            "credential",
        ];
        for out in [&reg, &sel, &stats] {
            let lower = out.to_lowercase();
            for needle in FORBIDDEN {
                assert!(!lower.contains(needle), "leaked '{needle}' in: {out}");
            }
        }
        kvn_core_destroy(h);
    }
}
