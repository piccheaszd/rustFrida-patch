//! JS API: Java._methods(class) — enumerate methods via JNI reflection

use crate::ffi;
use crate::value::JSValue;
use std::collections::HashSet;
use std::ffi::CString;

use super::jni_core::*;
use super::reflect::*;

// ============================================================================
// JS API: Java._methods(class) — enumerate methods via JNI reflection
// ============================================================================

pub(super) unsafe extern "C" fn js_java_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"_methods() requires 1 argument: className\0".as_ptr() as *const _);
    }

    let class_arg = JSValue(*argv);
    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::JS_ThrowTypeError(ctx, b"argument must be a class name string\0".as_ptr() as *const _),
    };

    let mut methods = if crate::is_raw_clone_js_thread() {
        match super::art_method::enumerate_methods_by_dex(std::ptr::null_mut(), &class_name) {
            Some(m) => m,
            None => match super::callback::enumerate_methods_via_executor(&class_name) {
                Ok(m) => m,
                Err(msg) => {
                    let err = CString::new(format!(
                        "raw clone _methods('{}') dex self-parse and Java executor reflection failed: {}",
                        class_name, msg
                    ))
                    .unwrap();
                    return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
                }
            },
        }
    } else {
        let env = match ensure_jni_initialized() {
            Ok(e) => e,
            Err(msg) => {
                let err = CString::new(msg).unwrap();
                return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
            }
        };
        match enumerate_methods(env, &class_name) {
            Ok(m) => m,
            Err(msg) => {
                let err = CString::new(msg).unwrap();
                return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
            }
        }
    };

    // Registry entries may include methods installed with a raw JNI signature
    // before reflection has cached the class. They should supplement, not
    // replace, reflection results; replacing drops inherited methods such as
    // java.lang.Object.getClass().
    let mut seen: HashSet<(String, String, bool)> = methods
        .iter()
        .map(|m| (m.name.clone(), m.sig.clone(), m.is_static))
        .collect();
    for method in super::callback::registered_methods_for_class(&class_name) {
        let key = (method.name.clone(), method.sig.clone(), method.is_static);
        if seen.insert(key) {
            methods.push(method);
        }
    }

    // Build JS array: [{name: "...", sig: "...", static: bool}, ...]
    let arr = ffi::JS_NewArray(ctx);
    for (i, m) in methods.iter().enumerate() {
        let obj = ffi::JS_NewObject(ctx);
        let obj_val = JSValue(obj);

        let name_val = JSValue::string(ctx, &m.name);
        let sig_val = JSValue::string(ctx, &m.sig);
        let static_val = JSValue::bool(m.is_static);
        let modifiers_val = JSValue::int(m.modifiers);

        obj_val.set_property(ctx, "name", name_val);
        obj_val.set_property(ctx, "sig", sig_val);
        obj_val.set_property(ctx, "static", static_val);
        obj_val.set_property(ctx, "modifiers", modifiers_val);

        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, obj);
    }

    arr
}
