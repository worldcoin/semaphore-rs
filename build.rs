use color_eyre::eyre::Result;
use std::{
    fs::{create_dir, File},
    path::{Component, Path, PathBuf},
};
use wasmer::Cranelift;

extern crate reqwest;

const SEMAPHORE_FILES_PATH: &str = "semaphore_files";
const SEMAPHORE_DOWNLOAD_URL: &str = "https://www.trusted-setup-pse.org/semaphore";

#[cfg(feature = "depth_30")]
static SUPPORTED_DEPTH: usize = 30;
#[cfg(feature = "depth_20")]
static SUPPORTED_DEPTH: usize = 20;
#[cfg(feature = "depth_16")]
static SUPPORTED_DEPTH: usize = 16;

// See <https://internals.rust-lang.org/t/path-to-lexical-absolute/14940>
fn absolute(path: PathBuf) -> Result<PathBuf> {
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

fn download_and_store_binary(url: &str, path: &Path) -> Result<()> {
    let mut resp = reqwest::blocking::get(url).expect(&format!("Failed to download file: {url}"));
    let path_str = path.to_str().unwrap();
    let mut file = File::create(path).expect(&format!("Failed to create file: {path_str}"));
    resp.copy_to(&mut file)?;
    Ok(())
}

fn semaphore_file_path(file_name: &str) -> PathBuf {
    Path::new(SEMAPHORE_FILES_PATH)
        .join(&SUPPORTED_DEPTH.to_string())
        .join(file_name)
}

fn build_circuit() -> Result<()> {
    let base_path = Path::new(SEMAPHORE_FILES_PATH);
    if !base_path.exists() {
        create_dir(base_path)?;
    }

    let depth_str = &SUPPORTED_DEPTH.to_string();
    let extensions = ["wasm", "zkey"];

    let depth_subfolder = base_path.join(depth_str);
    if !Path::new(&depth_subfolder).exists() {
        create_dir(&depth_subfolder)?;
    }

    for extension in extensions {
        let filename = "semaphore";
        let download_url = format!("{SEMAPHORE_DOWNLOAD_URL}/{depth_str}/{filename}.{extension}");
        let path = Path::new(&depth_subfolder).join(format!("{filename}.{extension}"));
        download_and_store_binary(&download_url, &path)?;
    }

    // Compute absolute paths
    let zkey_file = absolute(semaphore_file_path("semaphore.zkey"))?;
    let wasm_file = absolute(semaphore_file_path("semaphore.wasm"))?;

    assert!(zkey_file.exists());
    assert!(wasm_file.exists());

    // Export generated paths
    println!("cargo:rustc-env=BUILD_RS_ZKEY_FILE={}", zkey_file.display());
    println!("cargo:rustc-env=BUILD_RS_WASM_FILE={}", wasm_file.display());

    Ok(())
}

#[cfg(feature = "dylib")]
fn build_dylib() -> Result<()> {
    use color_eyre::eyre::eyre;
    use enumset::enum_set;
    use std::{env, str::FromStr};
    use wasmer::{Module, Store, Target, Triple};
    use wasmer_compiler_cranelift::Cranelift;
    use wasmer_engine_dylib::Dylib;

    let wasm_file = absolute(semaphore_file_path("semaphore.wasm"))?;
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
    let engine = Dylib::new(Cranelift::default()).target(target).engine();

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
    #[cfg(feature = "dylib")]
    build_dylib()?;
    Ok(())
}
