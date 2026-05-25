use std::path::Path;
use std::time::SystemTime;

fn main() {
    let target = std::env::var("TARGET").expect("TARGET not set");
    let profile = std::env::var("PROFILE").expect("PROFILE not set");
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir.parent().expect("rust_frida must be inside workspace root");
    let profile_dir = if profile == "release" { "release" } else { "debug" };
    let agent_build_flag = if profile_dir == "release" { " --release" } else { "" };
    let agent_so = workspace_root
        .join("target")
        .join(&target)
        .join(profile_dir)
        .join("libagent.so");

    // 当 agent.so 变化时重新编译 host（include_bytes! 缓存问题）
    println!("cargo::rerun-if-changed={}", agent_so.display());
    println!("cargo::rerun-if-changed=../loader/build/bootstrapper.bin");
    println!("cargo::rerun-if-changed=../loader/build/rustfrida-loader.bin");

    let mut newest_agent_input = SystemTime::UNIX_EPOCH;
    watch_inputs(
        workspace_root.join("agent").join("Cargo.toml").as_path(),
        &mut newest_agent_input,
    );
    watch_inputs(
        workspace_root.join("agent").join("build.rs").as_path(),
        &mut newest_agent_input,
    );
    watch_inputs(
        workspace_root.join("agent").join("src").as_path(),
        &mut newest_agent_input,
    );
    watch_inputs(
        workspace_root.join("quickjs-hook").join("Cargo.toml").as_path(),
        &mut newest_agent_input,
    );
    watch_inputs(
        workspace_root.join("quickjs-hook").join("build.rs").as_path(),
        &mut newest_agent_input,
    );
    watch_inputs(
        workspace_root.join("quickjs-hook").join("src").as_path(),
        &mut newest_agent_input,
    );

    match std::fs::metadata(&agent_so).and_then(|meta| meta.modified()) {
        Ok(agent_mtime) if agent_mtime >= newest_agent_input => {}
        Ok(_) => {
            panic!(
                "embedded agent is stale: run `cargo build -p agent{}` before building rust_frida",
                agent_build_flag
            );
        }
        Err(e) => {
            panic!(
                "missing embedded agent {}: {}. Run `cargo build -p agent{}` first",
                agent_so.display(),
                e,
                agent_build_flag
            );
        }
    }

    if std::env::var_os("CARGO_FEATURE_QBDI").is_some() {
        let helper_path = format!(
            "{}/target/{}/{}/libqbdi_helper.so",
            workspace_root.display(),
            target,
            profile_dir
        );
        println!("cargo:rustc-env=QBDI_HELPER_SO_PATH={}", helper_path);
        println!("cargo:rerun-if-changed={}", helper_path);
    }
}

fn watch_inputs(path: &Path, newest: &mut SystemTime) {
    if !path.exists() {
        return;
    }
    println!("cargo::rerun-if-changed={}", path.display());
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.is_file() {
        if let Ok(modified) = meta.modified() {
            if modified > *newest {
                *newest = modified;
            }
        }
        return;
    }
    if !meta.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        watch_inputs(entry.path().as_path(), newest);
    }
}
