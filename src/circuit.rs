use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::Lazy;
use std::{io::Cursor, sync::Mutex};
// use wasmer::{Dylib, Module, Store};

const ZKEY_BYTES: &[u8] = include_bytes!("../semaphore/build/snark/semaphore_final.zkey");

pub const WASM: &[u8] = include_bytes!("../semaphore/build/snark/semaphore.wasm");

pub static ZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    let mut reader = Cursor::new(ZKEY_BYTES);
    read_zkey(&mut reader).expect("zkey should be valid")
});

// pub static WITNESS_CALCULATOR: Lazy<WitnessCalculator> = Lazy::new(|| {
//     // Create Wasm module
//     let module = if let Some(path) = option_env!("CIRCUIT_WASM_DYLIB") {
//         let store = Store::new(&Dylib::headless().engine());
//         // The module must be exported using [`Module::serialize`].
//         unsafe {
//             Module::deserialize_from_file(&store, path).expect("Failed to load wasm dylib module")
//         }
//     } else {
//         let store = Store::default();
//         Module::from_binary(&store, WASM).expect("wasm should be valid")
//     };

//     // Create witness calculator
//     let result =
//         WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
//     // Mutex::new(result)
//     result
// });
