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

    let target = std::env::var("TARGET")?;
    let profile = std::env::var("PROFILE")?;
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir.parent().expect("agent must be inside workspace root");
    let profile_dir = if profile == "release" { "release" } else { "debug" };
    let marker = workspace_root
        .join("target")
        .join(target)
        .join(profile_dir)
        .join("libagent.features");
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let noptrace = std::env::var_os("CARGO_FEATURE_NOPTRACE").is_some();
    std::fs::write(marker, format!("noptrace={}\n", if noptrace { "1" } else { "0" }))?;

    Ok(())
}
