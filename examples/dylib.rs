use wasmer::{Module, Store};
use wasmer_compiler_cranelift::Cranelift;
use wasmer_engine_dylib::Dylib;

const PATH: &str = "../semaphore/build/snark/semaphore.wasm";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define a compiler configuration.
    //
    // In this situation, the compiler is
    // `wasmer_compiler_cranelift`. The compiler is responsible to
    // compile the Wasm module into executable code.
    let compiler_config = Cranelift::default();

    println!("Creating Dylib engine...");
    // Define the engine that will drive everything.
    //
    // In this case, the engine is `wasmer_engine_dylib` which means
    // that a shared object is going to be generated.
    let engine = Dylib::new(compiler_config).engine();

    // Create a store, that holds the engine.
    let store = Store::new(&engine);

    println!("Compiling module...");
    // Here we go.
    //
    // Let's compile the Wasm module. It is at this step that the Wasm
    // text is transformed into Wasm bytes (if necessary), and then
    // compiled to executable code by the compiler, which is then
    // stored into a shared object by the engine.
    let module = Module::from_file(&store, "../semaphore/build/snark/semaphore.wasm")?;

    println!("Storing as \"{}\"", PATH);
    module.serialize_to_file(PATH)?;

    println!("Done! you can now compile with CIRCUIT_WASM_DYLIB=\"{}\"", PATH);

    Ok(())
}
