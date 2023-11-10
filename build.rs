use std::{
    fs::{create_dir, create_dir_all, File},
    path::Path,
};

use color_eyre::eyre::Result;

extern crate reqwest;

const SEMAPHORE_FILES_PATH: &str = "semaphore_files";
const SEMAPHORE_DOWNLOAD_URL: &str = "https://www.trusted-setup-pse.org/semaphore";

fn download_and_store_binary(url: &str, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();

    let mut resp =
        reqwest::blocking::get(url).unwrap_or_else(|_| panic!("Failed to download file: {url}"));
    let mut file =
        File::create(path).unwrap_or_else(|_| panic!("Failed to create file: {}", path.display()));

    resp.copy_to(&mut file)?;
    Ok(())
}

fn build_circuit(depth: usize) -> Result<()> {
    let out_dir = std::env::var("OUT_DIR").expect("Missing out dir var");
    let base_path = Path::new(&out_dir).join(SEMAPHORE_FILES_PATH);

    if !base_path.exists() {
        create_dir_all(&base_path)?;
    }

    let depth_str = &depth.to_string();
    let extensions = ["zkey"];

    let depth_subfolder = base_path.join(&depth_str);
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
    let zkey_file = absolute(semaphore_file_path("semaphore.zkey", depth))?;
    let graph_file = absolute(Path::new("graphs")
    .join(depth.to_string())
    .join("graph.bin"))?;

    assert!(zkey_file.exists());
    assert!(graph_file.exists());

    // Export generated paths
    println!(
        "cargo:rustc-env=BUILD_RS_ZKEY_FILE_{}={}",
        depth,
        zkey_file.display()
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
