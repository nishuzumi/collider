use std::path::Path;

// crates.io
use vergen::EmitBuilder;

fn main() {
    let mut emitter = EmitBuilder::builder();

    emitter.cargo_target_triple();

    // Disable the git version if installed from <crates.io>.
    if emitter
        .clone()
        .git_sha(true)
        .fail_on_error()
        .emit()
        .is_err()
    {
        println!("cargo:rustc-env=VERGEN_GIT_SHA=crates.io");

        emitter
    } else {
        *emitter.git_sha(true)
    }
    .emit()
    .unwrap();

    let op_sha256_exists = Path::new("src/miner/op_sha256_gpu.rs").exists();

    if op_sha256_exists {
        println!("cargo:rustc-cfg=feature=\"op_sha256\"");
    }
}
