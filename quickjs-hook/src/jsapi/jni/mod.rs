mod api;

use crate::context::JSContext;
use crate::jsapi::console::output_message;

pub use api::register_jni_api;

pub fn load_jni_boot_script(ctx: &JSContext) {
    if crate::is_minimal_api_profile() {
        output_message("[jni_api] boot script skipped by minimal profile");
        return;
    }

    let boot = include_str!("jni_boot.js");
    match ctx.eval(boot, "<jni_boot>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => output_message(&format!("[jni_api] boot script error: {}", e)),
    }
}
