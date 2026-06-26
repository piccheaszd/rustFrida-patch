//! JavaScript API implementations

pub(crate) mod callback_util;
pub mod console;
#[cfg(feature = "file-api")]
pub mod file;
pub mod hook_api;
pub mod java;
#[cfg(feature = "jni-api")]
pub mod jni;
pub mod memory;
pub mod module;
pub mod ptr;
#[cfg(feature = "rpc-api")]
pub mod rpc;
pub(crate) mod util;

pub use console::register_console;
pub use hook_api::register_hook_api;
pub use java::deferred_java_init;
pub use memory::register_memory_api;
pub use ptr::register_ptr;

use crate::context::JSContext;

/// Register all JavaScript APIs
pub fn register_all_apis(ctx: &JSContext) {
    #[cfg(any(feature = "js-module-api", feature = "lazy-java-api"))]
    let minimal = crate::is_minimal_api_profile();

    register_console(ctx);
    #[cfg(feature = "file-api")]
    file::register_file_api(ctx);
    register_ptr(ctx);
    register_hook_api(ctx);
    #[cfg(feature = "jni-api")]
    jni::register_jni_api(ctx);
    register_memory_api(ctx);
    #[cfg(feature = "js-module-api")]
    if !minimal {
        module::register_module_api(ctx);
    }
    #[cfg(feature = "lazy-java-api")]
    if !minimal {
        java::register_lazy_java_api(ctx);
    }
    #[cfg(feature = "rpc-api")]
    rpc::register_rpc(ctx);
}
