use std::{env, fs, path::Path, process::Command};

fn main() {
    if cfg!(feature = "build-witness") {
        let witness_cpp = env::var("WITNESS_CPP").unwrap();
        let circuit_file = Path::new(&witness_cpp);
        let circuit_name = circuit_file.file_stem().unwrap().to_str().unwrap();

        let status = Command::new("circom")
            .args([
                fs::canonicalize(circuit_file).unwrap().to_str().unwrap(),
                "--c",
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let cpp = Path::new("./")
            .join(circuit_name.to_owned() + "_cpp")
            .join(circuit_name.to_owned() + ".cpp");

        println!("cargo:warning=\"{}\"", cpp.to_str().unwrap());

        let status = Command::new("./script/replace.sh")
            .arg(cpp.to_str().unwrap())
            .status()
            .unwrap();
        assert!(status.success());

        cxx_build::bridge("src/generate.rs")
            .file("src/circuit.cc")
            .flag_if_supported("-std=c++14")
            .flag_if_supported("-w")
            .flag_if_supported("-d")
            .flag_if_supported("-g")
            .compile("witness");

        println!("cargo:rerun-if-changed=src/main.rs");
        println!("cargo:rerun-if-changed=src/circuit.cc");
        println!("cargo:rerun-if-changed=include/circuit.h");
    }
}
