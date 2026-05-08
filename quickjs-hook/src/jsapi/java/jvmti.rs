//! ART JVMTI instance enumeration backend.
//!
//! This follows Frida's reliable `Java.choose()` path for modern ART:
//! load/register `libopenjdkjvmti.so`, obtain an ART-TI env, tag live
//! instances through JVMTI, and convert the returned jobjects to globals.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::jsapi::console::output_verbose;

use super::jni_core::{get_or_init_vm, jni_check_exc, jni_fn_ptr, JniEnv, NewGlobalRefFn, JNI_NEW_GLOBAL_REF};

const JNI_OK: i32 = 0;
const K_ART_TI_VERSION: i32 = 0x7001_0200;
const JVMTI_ITERATION_CONTINUE: i32 = 1;
const JVMTI_HEAP_OBJECT_EITHER: i32 = 3;
const JVMTI_ERROR_NONE: i32 = 0;

const JVMTI_DEALLOCATE: usize = 47;
const JVMTI_SET_TAG: usize = 107;
const JVMTI_ITERATE_OVER_INSTANCES_OF_CLASS: usize = 112;
const JVMTI_GET_OBJECTS_WITH_TAGS: usize = 114;
const JVMTI_ADD_CAPABILITIES: usize = 142;

static NEXT_TAG: AtomicI64 = AtomicI64::new(0x7275_7374_6672_0001);

type JavaVmGetEnvFn = unsafe extern "C" fn(*mut c_void, *mut *mut c_void, i32) -> i32;
type ArtPluginInitializeFn = unsafe extern "C" fn() -> bool;

type JvmtiDeallocateFn = unsafe extern "C" fn(*mut c_void, *mut u8) -> i32;
type JvmtiSetTagFn = unsafe extern "C" fn(*mut c_void, *mut c_void, i64) -> i32;
type JvmtiAddCapabilitiesFn = unsafe extern "C" fn(*mut c_void, *const u64) -> i32;
type JvmtiIterateOverInstancesOfClassFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, i32, JvmtiHeapObjectCallback, *mut c_void) -> i32;
type JvmtiGetObjectsWithTagsFn =
    unsafe extern "C" fn(*mut c_void, i32, *const i64, *mut i32, *mut *mut *mut c_void, *mut *mut i64) -> i32;
type JvmtiHeapObjectCallback = unsafe extern "C" fn(i64, i64, *mut i64, *mut c_void) -> i32;

unsafe extern "C" fn tag_matching_object(
    _class_tag: i64,
    _size: i64,
    tag_ptr: *mut i64,
    user_data: *mut c_void,
) -> i32 {
    if !tag_ptr.is_null() {
        *tag_ptr = user_data as isize as i64;
    }
    JVMTI_ITERATION_CONTINUE
}

pub(super) unsafe fn jvmti_enumerate_instances(
    env: JniEnv,
    target_cls: *mut c_void,
    max_count: usize,
) -> Result<Vec<*mut c_void>, String> {
    let jvmti = get_or_init_jvmti_env()?;
    add_tagging_capability(jvmti)?;

    let tag = NEXT_TAG.fetch_add(1, Ordering::Relaxed);
    if tag == 0 {
        return Err("internal tag counter wrapped to zero".to_string());
    }

    let iterate: JvmtiIterateOverInstancesOfClassFn =
        std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_ITERATE_OVER_INSTANCES_OF_CLASS));
    let ret = iterate(
        jvmti,
        target_cls,
        JVMTI_HEAP_OBJECT_EITHER,
        tag_matching_object,
        tag as isize as *mut c_void,
    );
    if ret != JVMTI_ERROR_NONE {
        return Err(format!("IterateOverInstancesOfClass failed: {}", ret));
    }

    let get_objects: JvmtiGetObjectsWithTagsFn = std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_GET_OBJECTS_WITH_TAGS));
    let mut count: i32 = 0;
    let mut objects: *mut *mut c_void = ptr::null_mut();
    let mut tags: *mut i64 = ptr::null_mut();
    let ret = get_objects(jvmti, 1, &tag, &mut count, &mut objects, &mut tags);
    if ret != JVMTI_ERROR_NONE {
        return Err(format!("GetObjectsWithTags failed: {}", ret));
    }

    let new_global_ref: NewGlobalRefFn = std::mem::transmute(jni_fn_ptr(env, JNI_NEW_GLOBAL_REF));
    let set_tag: JvmtiSetTagFn = std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_SET_TAG));

    let cap = if max_count == 0 { usize::MAX } else { max_count };
    let n = (count.max(0) as usize).min(cap);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let obj = *objects.add(i);
        if obj.is_null() {
            continue;
        }
        let g = new_global_ref(env, obj);
        let _ = set_tag(jvmti, obj, 0);
        if jni_check_exc(env) || g.is_null() {
            continue;
        }
        out.push(g);
    }

    for i in n..count.max(0) as usize {
        let obj = *objects.add(i);
        if !obj.is_null() {
            let _ = set_tag(jvmti, obj, 0);
        }
    }

    deallocate_if_nonnull(jvmti, objects as *mut u8);
    deallocate_if_nonnull(jvmti, tags as *mut u8);
    Ok(out)
}

unsafe fn get_or_init_jvmti_env() -> Result<*mut c_void, String> {
    let vm = get_or_init_vm()?;
    if let Some(env) = try_get_jvmti_env(vm) {
        return Ok(env);
    }

    let handle = load_openjdk_jvmti()?;
    let init = resolve_art_plugin_initialize(handle)?;
    if !init() {
        return Err("ArtPlugin_Initialize returned false".to_string());
    }
    output_verbose("[jvmti] ArtPlugin_Initialize ok");

    try_get_jvmti_env(vm).ok_or_else(|| "JavaVM.GetEnv(kArtTiVersion) failed after plugin init".to_string())
}

unsafe fn try_get_jvmti_env(vm: *mut c_void) -> Option<*mut c_void> {
    let vm_table = *(vm as *const *const *const c_void);
    let get_env: JavaVmGetEnvFn = std::mem::transmute(*vm_table.add(6));
    let mut env: *mut c_void = ptr::null_mut();
    let ret = get_env(vm, &mut env, K_ART_TI_VERSION);
    (ret == JNI_OK && !env.is_null()).then_some(env)
}

unsafe fn load_openjdk_jvmti() -> Result<*mut c_void, String> {
    let paths = [
        "/apex/com.android.art/lib64/libopenjdkjvmti.so",
        "/apex/com.android.art/lib/libopenjdkjvmti.so",
        "libopenjdkjvmti.so",
    ];
    for path in paths {
        let handle =
            crate::jsapi::module::module_dlopen_load_from_libart_namespace(path, libc::RTLD_NOW | libc::RTLD_GLOBAL);
        if !handle.is_null() {
            output_verbose(&format!("[jvmti] loaded {}", path));
            return Ok(handle);
        }
    }
    Err("dlopen(libopenjdkjvmti.so) failed".to_string())
}

unsafe fn resolve_art_plugin_initialize(handle: *mut c_void) -> Result<ArtPluginInitializeFn, String> {
    let sym_name = std::ffi::CString::new("ArtPlugin_Initialize").unwrap();
    let sym = libc::dlsym(handle, sym_name.as_ptr());
    if sym.is_null() {
        return Err("dlsym(ArtPlugin_Initialize) failed".to_string());
    }
    Ok(std::mem::transmute(sym))
}

unsafe fn add_tagging_capability(jvmti: *mut c_void) -> Result<(), String> {
    let add_capabilities: JvmtiAddCapabilitiesFn = std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_ADD_CAPABILITIES));
    let capabilities: u64 = 1;
    let ret = add_capabilities(jvmti, &capabilities);
    if ret == JVMTI_ERROR_NONE {
        Ok(())
    } else {
        Err(format!("AddCapabilities(can_tag_objects) failed: {}", ret))
    }
}

unsafe fn deallocate_if_nonnull(jvmti: *mut c_void, ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let deallocate: JvmtiDeallocateFn = std::mem::transmute(jvmti_fn_ptr(jvmti, JVMTI_DEALLOCATE));
    let _ = deallocate(jvmti, ptr);
}

unsafe fn jvmti_fn_ptr(jvmti: *mut c_void, one_based_index: usize) -> *const c_void {
    let table = *(jvmti as *const *const *const c_void);
    *table.add(one_based_index - 1)
}
