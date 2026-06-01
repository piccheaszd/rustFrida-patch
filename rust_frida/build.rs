use std::path::Path;
use std::time::SystemTime;

fn main() {
    let target = std::env::var("TARGET").expect("TARGET not set");
    let profile = std::env::var("PROFILE").expect("PROFILE not set");
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir.parent().expect("rust_frida must be inside workspace root");
    let profile_dir = if profile == "release" { "release" } else { "debug" };
    let noptrace = std::env::var_os("CARGO_FEATURE_NOPTRACE").is_some();
    let release_flag = if profile_dir == "release" { " --release" } else { "" };
    let agent_feature_flag = if noptrace {
        " --no-default-features --features quickjs,noptrace"
    } else {
        ""
    };
    let agent_build_flag = format!("{}{}", release_flag, agent_feature_flag);
    let agent_so = workspace_root
        .join("target")
        .join(&target)
        .join(profile_dir)
        .join("libagent.so");
    let agent_feature_marker = workspace_root
        .join("target")
        .join(&target)
        .join(profile_dir)
        .join("libagent.features");

    // 当 agent.so 变化时重新编译 host（include_bytes! 缓存问题）
    println!("cargo::rerun-if-changed={}", agent_so.display());
    println!("cargo::rerun-if-changed={}", agent_feature_marker.display());
    println!("cargo::rerun-if-changed=../loader/build/bootstrapper.bin");
    println!("cargo::rerun-if-changed=../loader/build/rustfrida-loader.bin");

    let loader_build_script = workspace_root.join("loader").join("build_helpers.py");
    let loader_helpers = workspace_root.join("loader").join("helpers");
    let loader_bootstrapper = workspace_root.join("loader").join("build").join("bootstrapper.bin");
    let loader_blob = workspace_root.join("loader").join("build").join("rustfrida-loader.bin");
    let mut newest_loader_input = SystemTime::UNIX_EPOCH;
    watch_inputs(loader_build_script.as_path(), &mut newest_loader_input);
    watch_inputs(loader_helpers.as_path(), &mut newest_loader_input);
    ensure_generated_blob(
        &loader_bootstrapper,
        newest_loader_input,
        "python3 loader/build_helpers.py",
    );
    ensure_generated_blob(&loader_blob, newest_loader_input, "python3 loader/build_helpers.py");

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

    let expected_agent_feature = if noptrace { "noptrace=1" } else { "noptrace=0" };
    match std::fs::read_to_string(&agent_feature_marker) {
        Ok(features) if features.lines().any(|line| line.trim() == expected_agent_feature) => {}
        Ok(features) => {
            panic!(
                "embedded agent feature mismatch: expected {}, got {:?}. Run `cargo build -p agent{}` first",
                expected_agent_feature,
                features.trim(),
                agent_build_flag
            );
        }
        Err(e) => {
            panic!(
                "missing embedded agent feature marker {}: {}. Run `cargo build -p agent{}` first",
                agent_feature_marker.display(),
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

fn ensure_generated_blob(blob: &Path, newest_input: SystemTime, command: &str) {
    match std::fs::metadata(blob).and_then(|meta| meta.modified()) {
        Ok(blob_mtime) if blob_mtime >= newest_input => {}
        Ok(_) => {
            panic!(
                "embedded loader blob is stale: run `{}` before building rust_frida ({})",
                command,
                blob.display()
            );
        }
        Err(e) => {
            panic!(
                "missing embedded loader blob {}: {}. Run `{}` first",
                blob.display(),
                e,
                command
            );
        }
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
