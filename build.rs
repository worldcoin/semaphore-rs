use color_eyre::eyre::Result;
use std::{
    fs::{create_dir, File},
    path::{Component, Path, PathBuf},
};

extern crate reqwest;

use ark_zkey;

const SEMAPHORE_FILES_PATH: &str = "semaphore_files";
const SEMAPHORE_DOWNLOAD_URL: &str = "https://www.trusted-setup-pse.org/semaphore";

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
    let mut resp =
        reqwest::blocking::get(url).unwrap_or_else(|_| panic!("Failed to download file: {url}"));
    let path_str = path.to_str().unwrap();
    let mut file =
        File::create(path).unwrap_or_else(|_| panic!("Failed to create file: {path_str}"));
    resp.copy_to(&mut file)?;
    Ok(())
}

fn semaphore_file_path(file_name: &str, depth: usize) -> PathBuf {
    Path::new(SEMAPHORE_FILES_PATH)
        .join(depth.to_string())
        .join(file_name)
}

fn create_arkzkey(path: PathBuf) -> Result<PathBuf> {
    let mut ark_zkey_path = path.clone();
    ark_zkey_path.set_extension("arkzkey");

    let (original_proving_key, original_constraint_matrices) =
        ark_zkey::read_proving_key_and_matrices_from_zkey(
            path.to_str().expect("Failed to convert path."),
        )?;

    ark_zkey::convert_zkey(
        original_proving_key,
        original_constraint_matrices,
        ark_zkey_path.to_str().unwrap(),
    )?;

    Ok(ark_zkey_path)
}

fn build_circuit(depth: usize) -> Result<()> {
    let base_path = Path::new(SEMAPHORE_FILES_PATH);
    if !base_path.exists() {
        create_dir(base_path)?;
    }

    let depth_str = &depth.to_string();
    let extensions = ["zkey"];

    let depth_subfolder = base_path.join(depth_str);
    if !Path::new(&depth_subfolder).exists() {
        create_dir(&depth_subfolder)?;
    }

    for extension in extensions {
        let filename = "semaphore";
        let download_url = format!("{SEMAPHORE_DOWNLOAD_URL}/{depth_str}/{filename}.{extension}");
        let path = Path::new(&depth_subfolder).join(format!("{filename}.{extension}"));
        download_and_store_binary(&download_url, &path)?;
        create_arkzkey(path)?;
    }

    // Compute absolute paths
    let zkey_file = absolute(semaphore_file_path("semaphore.zkey", depth))?;
    let arkzkey_file = absolute(semaphore_file_path("semaphore.arkzkey", depth))?;
    let graph_file = absolute(
        Path::new("graphs")
            .join(depth.to_string())
            .join("graph.bin"),
    )?;

    assert!(zkey_file.exists());
    assert!(arkzkey_file.exists());
    assert!(graph_file.exists());

    // Export generated paths
    println!(
        "cargo:rustc-env=BUILD_RS_ZKEY_FILE_{}={}",
        depth,
        zkey_file.display()
    );
    println!(
        "cargo:rustc-env=BUILD_RS_ARKZKEY_FILE_{}={}",
        depth,
        arkzkey_file.display()
    );
    println!(
        "cargo:rustc-env=BUILD_RS_GRAPH_FILE_{}={}",
        depth,
        graph_file.display()
    );

    Ok(())
}

fn main() -> Result<()> {
    for depth in semaphore_depth_config::get_supported_depths() {
        build_circuit(*depth)?;
    }
    Ok(())
}
