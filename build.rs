use color_eyre::eyre::{eyre, Result};
use std::{
    path::{Component, Path, PathBuf},
    fs::{File, create_dir}
};
use std::io;
extern crate reqwest;

const SEMAPHORE_FILES_PATH: &str = "semaphore_files";
const SEMAPHORE_DOWNLOAD_URL: &str = "https://www.trusted-setup-pse.org/semaphore";

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

fn fetch_url(url: String, file_name: &str) -> Result<()> {
    let resp = reqwest::blocking::get(url).expect("failed to download file");
    let body = resp.text().expect("body invalid");
    let mut out = File::create(file_name).expect("failed to create file");
    io::copy(&mut body.as_bytes(), &mut out).expect("failed to copy content");
    Ok(())
}

fn build_circuit(depth: i8) -> Result<()> {
    if !Path::new(SEMAPHORE_FILES_PATH).exists() {
        create_dir(SEMAPHORE_FILES_PATH)?;
    }

    let depth = &depth.to_string()[..];
    let extensions = ["wasm", "zkey"];

    let folder = [SEMAPHORE_FILES_PATH, &depth].join("/");
    if !Path::new(&folder).exists() {
        create_dir(&folder)?;
    }

    for extension in extensions {
        let filename = ["semaphore", extension].join(".");
        let download_url = [SEMAPHORE_DOWNLOAD_URL, &depth, &filename].join("/");
        let path = [SEMAPHORE_FILES_PATH, &depth, &filename].join("/");
        fetch_url(download_url, &path)?;
    }

    // Compute absolute paths
    let zkey_file = absolute(&[SEMAPHORE_FILES_PATH, &depth, "semaphore.zkey"].join("/"))?;
    let wasm_file = absolute(&[SEMAPHORE_FILES_PATH, &depth, "semaphore.wasm"].join("/"))?;

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
    build_circuit(16)?;
    #[cfg(feature = "dylib")]
    build_dylib()?;
    Ok(())
}
