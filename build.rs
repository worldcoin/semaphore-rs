// TODO: Use ExitCode::exit_ok() when stable.

use std::{process::Command, fs::canonicalize, path::{Path, PathBuf, Component}};
use color_eyre::eyre::{Result, eyre};

const ZKEY_FILE: &str = "./semaphore/build/snark/semaphore_final.zkey";
const WASM_FILE: &str = "./semaphore/build/snark/semaphore.wasm";
const DYLIB_FILE: &str = "./semaphore/build/snark/semaphore.dylib";

// See <https://internals.rust-lang.org/t/path-to-lexical-absolute/14940>
fn absolute(path: &str) -> Result<PathBuf> {
    let path = Path::new(path);
    let mut absolute = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir()?
    };
    for component in path.components() {
        match component {
            Component::CurDir => {},
            Component::ParentDir => { absolute.pop(); },
            component @ _ => absolute.push(component.as_os_str()),
        }
    }
    Ok(absolute)
}

fn build_circuit() -> Result<()> {
    println!("cargo:rerun-if-changed=./semaphore");
    let run = |cmd: &[&str]| -> Result<()> {
        Command::new(cmd[0])
            .args(cmd[1..].iter())
            .current_dir("./semaphore")
            .status()?
            .success()
            .then(|| ())
            .ok_or(eyre!("procees returned failure"))?;
            Ok(())
    };

    // Compute absolute paths
    let zkey_file = absolute(ZKEY_FILE)?;
    let wasm_file = absolute(WASM_FILE)?;

    // Build circuits if not exists
    // TODO: This does not rebuild if the semaphore submodule is changed. 
    // NOTE: This requires npm / nodejs to be installed.
    if !(zkey_file.exists() && wasm_file.exists()) {
        run(&["npm", "install"])?;
        run(&["npm", "exec", "ts-node", "./scripts/compile-circuits.ts"])?;
    }
    assert!(zkey_file.exists());
    assert!(wasm_file.exists());

    // Export generated paths
    println!("cargo:rustc-env=ZKEY_FILE={}", zkey_file.display());
    println!("cargo:rustc-env=WASM_FILE={}", wasm_file.display());
    
    Ok(())
}

fn main() -> Result<()> {
    build_circuit()?;


    Ok(())
}
