use std::path::{Path, PathBuf};
use std::time::SystemTime;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let profile = std::env::var("PROFILE").expect("PROFILE not set");
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir.parent().expect("rust_frida must be inside workspace root");
    let profile_dir = if profile == "release" { "release" } else { "debug" };
    let noptrace = std::env::var_os("CARGO_FEATURE_NOPTRACE").is_some();
    println!("cargo:rerun-if-env-changed=RF_AGENT_API");
    let agent_api = std::env::var("RF_AGENT_API").unwrap_or_else(|_| "min".to_string());
    let full_api_agent = match agent_api.as_str() {
        "min" | "native-min" | "quickjs" => false,
        "full" | "full-api" | "quickjs-full-api" => true,
        other => panic!("unsupported RF_AGENT_API={}; use min or full", other),
    };

    let loader_inputs = [
        "loader/build_helpers.py",
        "loader/helpers/bootstrapper.c",
        "loader/helpers/elf-parser.c",
        "loader/helpers/elf-parser.h",
        "loader/helpers/helper.lds",
        "loader/helpers/inject-context.h",
        "loader/helpers/nolibc-compat.h",
        "loader/helpers/rustfrida-loader.c",
        "loader/helpers/syscall.c",
        "loader/helpers/syscall.h",
    ];
    for input in loader_inputs {
        println!("cargo:rerun-if-changed=../{}", input);
    }

    let loader_bootstrapper = workspace_root.join("loader").join("build").join("bootstrapper.bin");
    let loader_blob = workspace_root.join("loader").join("build").join("rustfrida-loader.bin");
    let loader_rx_size = workspace_root
        .join("loader")
        .join("build")
        .join("rustfrida-loader.rx_size");
    if target == "aarch64-linux-android" && helpers_are_stale(workspace_root) {
        let status = std::process::Command::new("uv")
            .args(["run", "--python", "3"])
            .arg(workspace_root.join("loader/build_helpers.py"))
            .current_dir(workspace_root)
            .status()
            .expect("failed to run loader/build_helpers.py");
        if !status.success() {
            panic!("loader/build_helpers.py failed with status {}", status);
        }
    }
    ensure_generated_blob(&loader_bootstrapper, "uv run --python 3 loader/build_helpers.py");
    ensure_generated_blob(&loader_blob, "uv run --python 3 loader/build_helpers.py");
    ensure_generated_blob(&loader_rx_size, "uv run --python 3 loader/build_helpers.py");

    let zymbiote_sources = [
        "zymbiote/build.sh",
        "zymbiote/zymbiote.c",
        "zymbiote/zymbiote_pure.c",
        "zymbiote/zymbiote_restore.c",
    ];
    for input in zymbiote_sources {
        println!("cargo:rerun-if-changed=../{}", input);
    }
    println!("cargo:rerun-if-changed=../zymbiote/build/zymbiote.elf");
    println!("cargo:rerun-if-changed=../zymbiote/build/zymbiote-pure.elf");
    println!("cargo:rerun-if-changed=../zymbiote/build/zymbiote-restore.elf");

    let target_profile_dir = current_target_profile_dir();
    let built_agent_so = target_profile_dir.join("libagent.so");
    let built_agent_feature_marker = target_profile_dir.join("libagent.features");
    let agent_variant = match (noptrace, full_api_agent) {
        (true, true) => "noptrace-full",
        (true, false) => "noptrace",
        (false, true) => "ptrace-full",
        (false, false) => "ptrace",
    };
    let agent_so = target_profile_dir.join(format!("libagent.{}.so", agent_variant));
    let agent_feature_marker = target_profile_dir.join(format!("libagent.{}.features", agent_variant));

    println!("cargo:rerun-if-changed={}", built_agent_so.display());
    println!("cargo:rerun-if-changed={}", built_agent_feature_marker.display());
    println!("cargo:rerun-if-changed={}", agent_so.display());
    println!("cargo:rerun-if-changed={}", agent_feature_marker.display());

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

    let release_flag = if profile_dir == "release" { " --release" } else { "" };
    let agent_feature_flag = match (noptrace, full_api_agent) {
        (true, true) => " --no-default-features --features quickjs-full-api,noptrace",
        (true, false) => " --no-default-features --features quickjs,noptrace",
        (false, true) => " --no-default-features --features quickjs-full-api",
        (false, false) => "",
    };
    let agent_build_flag = format!("{}{}", release_flag, agent_feature_flag);
    let expected_agent_features = [
        if noptrace { "noptrace=1" } else { "noptrace=0" },
        if full_api_agent { "full_api=1" } else { "full_api=0" },
    ];
    ensure_agent_variant(
        &built_agent_so,
        &built_agent_feature_marker,
        &agent_so,
        &agent_feature_marker,
        newest_agent_input,
        &expected_agent_features,
        &agent_build_flag,
    );
    println!("cargo:rustc-env=AGENT_SO_PATH={}", agent_so.display());

    if std::env::var_os("CARGO_FEATURE_QBDI").is_some() {
        let helper_path = target_profile_dir.join("libqbdi_helper.so");
        println!("cargo:rustc-env=QBDI_HELPER_SO_PATH={}", helper_path.display());
        println!("cargo:rerun-if-changed={}", helper_path.display());
    }
}

fn current_target_profile_dir() -> PathBuf {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    out_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("无法从 OUT_DIR 推导 target profile 目录: {}", out_dir.display()))
}

fn ensure_generated_blob(blob: &Path, command: &str) {
    if let Err(e) = std::fs::metadata(blob) {
        panic!(
            "missing embedded loader blob {}: {}. Run `{}` first",
            blob.display(),
            e,
            command
        );
    }
}

fn ensure_agent_variant(
    built_agent_so: &Path,
    built_marker: &Path,
    embedded_agent_so: &Path,
    embedded_marker: &Path,
    newest_input: SystemTime,
    expected_features: &[&str],
    agent_build_flag: &str,
) {
    if embedded_agent_is_current(embedded_agent_so, embedded_marker, newest_input, expected_features) {
        return;
    }

    let built_mtime = match std::fs::metadata(built_agent_so).and_then(|meta| meta.modified()) {
        Ok(mtime) => mtime,
        Err(e) => {
            panic!(
                "missing built agent {}: {}. Run `cargo build -p agent{}` first",
                built_agent_so.display(),
                e,
                agent_build_flag
            );
        }
    };

    if built_mtime < newest_input {
        panic!(
            "built agent is stale: run `cargo build -p agent{}` before building rust_frida",
            agent_build_flag
        );
    }

    let built_features = std::fs::read_to_string(built_marker).unwrap_or_else(|e| {
        panic!(
            "missing built agent feature marker {}: {}. Run `cargo build -p agent{}` first",
            built_marker.display(),
            e,
            agent_build_flag
        )
    });
    if !feature_marker_matches(&built_features, expected_features) {
        panic!(
            "built agent feature mismatch: expected {:?}, got {:?}. Run `cargo build -p agent{}` first",
            expected_features,
            built_features.trim(),
            agent_build_flag
        );
    }

    if let Some(parent) = embedded_agent_so.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| panic!("create {} failed: {}", parent.display(), e));
    }
    std::fs::copy(built_agent_so, embedded_agent_so).unwrap_or_else(|e| {
        panic!(
            "copy agent {} -> {} failed: {}",
            built_agent_so.display(),
            embedded_agent_so.display(),
            e
        )
    });
    std::fs::write(embedded_marker, format!("{}\n", expected_features.join("\n")))
        .unwrap_or_else(|e| panic!("write {} failed: {}", embedded_marker.display(), e));
}

fn embedded_agent_is_current(
    agent_so: &Path,
    marker: &Path,
    newest_input: SystemTime,
    expected_features: &[&str],
) -> bool {
    let Ok(agent_mtime) = std::fs::metadata(agent_so).and_then(|meta| meta.modified()) else {
        return false;
    };
    if agent_mtime < newest_input {
        return false;
    }
    let Ok(features) = std::fs::read_to_string(marker) else {
        return false;
    };
    feature_marker_matches(&features, expected_features)
}

fn feature_marker_matches(features: &str, expected_features: &[&str]) -> bool {
    expected_features
        .iter()
        .all(|expected| features.lines().any(|line| line.trim() == *expected))
}

fn helpers_are_stale(workspace_root: &Path) -> bool {
    let inputs = [
        "loader/build_helpers.py",
        "loader/helpers/bootstrapper.c",
        "loader/helpers/elf-parser.c",
        "loader/helpers/elf-parser.h",
        "loader/helpers/helper.lds",
        "loader/helpers/inject-context.h",
        "loader/helpers/nolibc-compat.h",
        "loader/helpers/rustfrida-loader.c",
        "loader/helpers/syscall.c",
        "loader/helpers/syscall.h",
    ];
    let outputs = [
        "loader/build/bootstrapper.bin",
        "loader/build/rustfrida-loader.bin",
        "loader/build/rustfrida-loader.rx_size",
    ];

    let newest_input = inputs
        .iter()
        .filter_map(|path| modified_time(&workspace_root.join(path)))
        .max();
    let oldest_output = outputs
        .iter()
        .map(|path| modified_time(&workspace_root.join(path)))
        .collect::<Option<Vec<_>>>()
        .and_then(|times| times.into_iter().min());

    match (newest_input, oldest_output) {
        (_, None) => true,
        (Some(input), Some(output)) => input > output,
        (None, Some(_)) => false,
    }
}

fn modified_time(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|metadata| metadata.modified()).ok()
}

fn watch_inputs(path: &Path, newest: &mut SystemTime) {
    if !path.exists() {
        return;
    }
    println!("cargo:rerun-if-changed={}", path.display());
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
