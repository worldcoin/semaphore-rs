use color_eyre::eyre::{eyre, Result};
use std::{
    path::{Component, Path, PathBuf},
    process::Command,
};

const ZKEY_FILE: &str = "./semaphore/build/snark/semaphore_final.zkey";
const WASM_FILE: &str = "./semaphore/build/snark/semaphore.wasm";

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
            Component::CurDir => {}
            Component::ParentDir => {
                absolute.pop();
            }
            component => absolute.push(component.as_os_str()),
        }
    }
    Ok(absolute)
}

fn build_circuit() -> Result<()> {
    println!("cargo:rerun-if-changed=./semaphore");
    let run = |cmd: &[&str]| -> Result<()> {
        // TODO: Use ExitCode::exit_ok() when stable.
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
    println!("cargo:rustc-env=BUILD_RS_ZKEY_FILE={}", zkey_file.display());
    println!("cargo:rustc-env=BUILD_RS_WASM_FILE={}", wasm_file.display());

    Ok(())
}

#[cfg(feature = "dylib")]
fn build_dylib() -> Result<()> {
    use enumset::enum_set;
    use std::{env, str::FromStr};
    use wasmer::{Module, Store, Target, Triple};
    use wasmer_compiler_cranelift::Cranelift;
    use wasmer_engine_dylib::Dylib;

    let wasm_file = absolute(WASM_FILE)?;
    assert!(wasm_file.exists());

    let out_dir = env::var("OUT_DIR")?;
    let out_dir = Path::new(&out_dir).to_path_buf();
    let dylib_file = out_dir.join("semaphore.dylib");
    println!(
        "cargo:rustc-env=CIRCUIT_WASM_DYLIB={}",
        dylib_file.display()
    );

    if dylib_file.exists() {
        return Ok(());
    }

    // Create a WASM engine for the target that can compile
    let triple = Triple::from_str(&env::var("TARGET")?).map_err(|e| eyre!(e))?;
    let cpu_features = enum_set!();
    let target = Target::new(triple, cpu_features);
    let compiler_config = Cranelift::default();
    let engine = Dylib::new(compiler_config).target(target).engine();

    // Compile the WASM module
    let store = Store::new(&engine);
    let module = Module::from_file(&store, &wasm_file)?;
    module.serialize_to_file(&dylib_file)?;
    assert!(dylib_file.exists());
    println!("cargo:warning=Circuit dylib is in {}", dylib_file.display());

    Ok(())
}

fn main() -> Result<()> {
    build_circuit()?;
    // #[cfg(feature = "dylib")]
    // build_dylib()?;
    Ok(())
}
