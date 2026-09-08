use std::path::PathBuf;

use color_eyre::eyre::{Result, WrapErr};

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    println!("cargo:rerun-if-changed=build.rs");

    for depth in semaphore_rs_depth_config::get_supported_depths() {
        for (directory, filename, variable) in [
            ("assets", "semaphore.arkzkey", "BUILD_RS_ARKZKEY_FILE"),
            ("graphs", "graph.bin", "BUILD_RS_GRAPH_FILE"),
        ] {
            let path = manifest_dir
                .join(directory)
                .join(depth.to_string())
                .join(filename);
            // Never fall back to a network download if a packaged artifact is missing.
            let path = path.canonicalize().wrap_err_with(|| {
                format!(
                    "Missing vendored Semaphore depth-{depth} artifact: {}",
                    path.display()
                )
            })?;
            println!("cargo:rerun-if-changed={}", path.display());
            println!("cargo:rustc-env={variable}_{depth}={}", path.display());
        }
    }

    Ok(())
}
