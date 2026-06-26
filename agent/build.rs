fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NOPTRACE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_QUICKJS_FULL_API");

    // 编译 C 代码
    cc::Build::new().file("src/transform.c").compile("my_c_lib");

    // Do not link hide_soinfo.c in the custom-linker injection path.
    // That code is only valid for Android linker/dlopen-managed modules; our
    // loader maps the agent itself, so no linker soinfo exists to hide.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,pthread_create,--export-dynamic-symbol=pthread_create");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,pthread_detach,--export-dynamic-symbol=pthread_detach");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,nanosleep,--export-dynamic-symbol=nanosleep");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-u,rustfrida_probe_entry,--export-dynamic-symbol=rustfrida_probe_entry");

    let marker = current_target_profile_dir()?.join("libagent.features");
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let noptrace = std::env::var_os("CARGO_FEATURE_NOPTRACE").is_some();
    let full_api = std::env::var_os("CARGO_FEATURE_QUICKJS_FULL_API").is_some();
    std::fs::write(
        marker,
        format!(
            "noptrace={}\nfull_api={}\n",
            if noptrace { "1" } else { "0" },
            if full_api { "1" } else { "0" }
        ),
    )?;

    Ok(())
}

fn current_target_profile_dir() -> anyhow::Result<std::path::PathBuf> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    out_dir
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("无法从 OUT_DIR 推导 target profile 目录: {}", out_dir.display()))
}
