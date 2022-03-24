//! This builds the wasm file into a dylib for a given target platform. 
//!
//! ```shell
//! cargo run --example dylib_ios aarch64-apple-ios semaphore/build/snark/semaphore.wasm semaphore/build/snark/semaphore.dylib
//! ```
//!
//! Ready?


use std::{str::FromStr};

use wasmer::{Module, Store, Triple, RuntimeError, CpuFeature, Target};
use wasmer_compiler_cranelift::Cranelift;
use wasmer_engine_dylib::Dylib;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    // to build for ios: aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios
    let target_os = std::env::args().nth(1).expect("no target given"); 
    let wasm_path = std::env::args().nth(2).expect("no wasm path given");
    let dylib_path = std::env::args().nth(3).expect("no dylib path given");

    // Define a compiler configuration.
    //
    // In this situation, the compiler is
    // `wasmer_compiler_cranelift`. The compiler is responsible to
    // compile the Wasm module into executable code.
    let compiler_config = Cranelift::default();

    let triple = Triple::from_str(&target_os)
        .map_err(|error| RuntimeError::new(error.to_string()))?;

    // Let's build the target.
    let mut cpu_feature = CpuFeature::set();
    cpu_feature.insert(CpuFeature::from_str("sse2")?);
    let target = Target::new(triple, cpu_feature);
    println!("Chosen target: {:?}", target);

    println!("Creating Dylib engine...");
    // Define the engine that will drive everything.
    //
    // In this case, the engine is `wasmer_engine_dylib` which means
    // that a shared object is going to be generated.
    let engine = Dylib::new(compiler_config).target(target).engine();

    // Create a store, that holds the engine.
    let store = Store::new(&engine);

    println!("Compiling module...");
    // Here we go.
    //
    // Let's compile the Wasm module. It is at this step that the Wasm
    // text is transformed into Wasm bytes (if necessary), and then
    // compiled to executable code by the compiler, which is then
    // stored into a shared object by the engine.
    let module = Module::from_file(&store, &wasm_path)?;

    module.serialize_to_file(&dylib_path)?;

    println!("Done! you can now compile with CIRCUIT_WASM_DYLIB=\"{}\"", &dylib_path);

    Ok(())
}
