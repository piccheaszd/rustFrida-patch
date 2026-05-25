fn main() -> anyhow::Result<()> {
    // 编译 C 代码
    cc::Build::new().file("src/transform.c").compile("my_c_lib");

    // Do not link hide_soinfo.c in the custom-linker injection path.
    // That code is only valid for Android linker/dlopen-managed modules; our
    // loader maps the agent itself, so no linker soinfo exists to hide.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,pthread_create,--export-dynamic-symbol=pthread_create");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,pthread_detach,--export-dynamic-symbol=pthread_detach");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,nanosleep,--export-dynamic-symbol=nanosleep");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,rustfrida_probe_entry,--export-dynamic-symbol=rustfrida_probe_entry");

    Ok(())
}
