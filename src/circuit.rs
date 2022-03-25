use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::Lazy;
use std::{io::Cursor, sync::Mutex};
use wasmer::{Module, Store};
use wasmer_engine_staticlib::{Staticlib, StaticlibArtifact};

const ZKEY_BYTES: &[u8] = include_bytes!(env!("BUILD_RS_ZKEY_FILE"));
const WASM_STATICLIB: &[u8] = include_bytes!("../semaphore.o");

pub static ZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    let mut reader = Cursor::new(ZKEY_BYTES);
    read_zkey(&mut reader).expect("zkey should be valid")
});

pub static WITNESS_CALCULATOR: Lazy<Mutex<WitnessCalculator>> = Lazy::new(|| {
    let store = Store::new(&Staticlib::headless().engine());
    let module =
    // Staticlib is generated in `build.rs` and should be valid.
    unsafe { Module::deserialize(&store, WASM_STATICLIB) }.expect("wasm should be valid");

    // Create witness calculator
    let result =
        WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
    Mutex::new(result)
});
