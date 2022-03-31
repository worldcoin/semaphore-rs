use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::{Lazy, OnceCell};
use std::{io::Cursor, sync::Mutex};
use wasmer::{BaseTunables, Cranelift, Dylib, Module, Pages, Store, Target, Universal};

use crate::tunables::LimitingTunables;

const ZKEY_BYTES: &[u8] = include_bytes!("../semaphore/build/snark/semaphore_final.zkey");

const WASM: &[u8] = include_bytes!("../semaphore/build/snark/semaphore.wasm");

const MEMORY_LIMIT: Option<&str> = option_env!("MEMORY_LIMIT");

pub static ZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    let mut reader = Cursor::new(ZKEY_BYTES);
    read_zkey(&mut reader).expect("zkey should be valid")
});

pub static WITNESS_CALCULATOR_DYLIB: OnceCell<String> = OnceCell::new();

pub static WITNESS_CALCULATOR: Lazy<Mutex<WitnessCalculator>> = Lazy::new(|| {
    // Create Wasm module
    let module = if let Some(path) = WITNESS_CALCULATOR_DYLIB.get() {
        let store = if let Some(memory_limit) = MEMORY_LIMIT {
            Store::new_with_tunables(
                &Dylib::headless().engine(),
                LimitingTunables::new(
                    BaseTunables::for_target(&Target::default()),
                    Pages(
                        memory_limit
                            .parse::<u32>()
                            .expect("MEMORY_LIMIT must be u32"),
                    ),
                ),
            )
        } else {
            Store::new(&Dylib::headless().engine())
        };

        // The module must be exported using [`Module::serialize`].
        unsafe {
            Module::deserialize_from_file(&store, path).expect("Failed to load wasm dylib module")
        }
    } else {
        let store = if let Some(memory_limit) = MEMORY_LIMIT {
            let compiler = Cranelift::default();
            let engine = Universal::new(compiler).engine();
            Store::new_with_tunables(
                &engine,
                LimitingTunables::new(
                    BaseTunables::for_target(&Target::default()),
                    Pages(
                        memory_limit
                            .parse::<u32>()
                            .expect("MEMORY_LIMIT must be u32"),
                    ),
                ),
            )
        } else {
            Store::default()
        };

        Module::from_binary(&store, WASM).expect("wasm should be valid")
    };

    // Create witness calculator
    let result =
        WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
    Mutex::new(result)
});
