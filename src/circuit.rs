use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::{Lazy, OnceCell};
use std::{io::Cursor, sync::Mutex};
use wasmer::{Module, Store};

use semaphore_depth_config::{get_depth_index, get_supported_depth_count};
use semaphore_depth_macros::array_for_depths;
#[cfg(feature = "dylib")]
use std::{env, path::Path};
#[cfg(feature = "dylib")]
use wasmer::Dylib;

const ZKEY_BYTES: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_ZKEY_FILE_", depth))));

#[cfg(not(feature = "dylib"))]
const WASM: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_WASM_FILE_", depth))));

static ZKEY: [Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)>; get_supported_depth_count()] =
    array_for_depths!(|depth| Lazy::new(|| {
        let mut reader = Cursor::new(ZKEY_BYTES[get_depth_index(depth).unwrap()]);
        read_zkey(&mut reader).expect("zkey should be valid")
    }));

static WITNESS_CALCULATOR: [OnceCell<Mutex<WitnessCalculator>>; get_supported_depth_count()] =
    array_for_depths!(|_| OnceCell::new());

/// Initialize the library.
#[cfg(feature = "dylib")]
pub fn initialize(dylib_path: &Path, depth: usize) {
    let index = get_depth_index(depth).expect(&format!("depth {} is not supported", depth));
    WITNESS_CALCULATOR[index]
        .set(from_dylib(dylib_path))
        .expect("Failed to initialize witness calculator");

    // Force init of ZKEY
    Lazy::force(&ZKEY[index]);
}

#[cfg(feature = "dylib")]
fn from_dylib(path: &Path) -> Mutex<WitnessCalculator> {
    let store = Store::new(&Dylib::headless().engine());
    // The module must be exported using [`Module::serialize`].
    let module = unsafe {
        Module::deserialize_from_file(&store, path).expect("Failed to load wasm dylib module")
    };
    let result =
        WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
    Mutex::new(result)
}

#[must_use]
pub fn zkey(depth: usize) -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
    let index = get_depth_index(depth).expect(&format!("depth {} is not supported", depth));
    &*ZKEY[index]
}

#[cfg(feature = "dylib")]
#[must_use]
pub fn witness_calculator(depth: usize) -> &'static Mutex<WitnessCalculator> {
    let index = get_depth_index(depth).expect(&format!("depth {} is not supported", depth));
    let var_name = format!("CIRCUIT_WASM_DYLIB_{}", depth);
    WITNESS_CALCULATOR[index].get_or_init(|| {
        let path =
            env::var(&var_name).expect(&format!(
            "Semaphore-rs is not initialized. The library needs to be initialized before use when \
             build with the `dylib` feature. You can initialize by calling `initialize` or \
             seting the `{}` environment variable.",var_name));
        from_dylib(Path::new(&path))
    })
}

#[cfg(not(feature = "dylib"))]
#[must_use]
pub fn witness_calculator(depth: usize) -> &'static Mutex<WitnessCalculator> {
    let index = get_depth_index(depth).expect(&format!("depth {} is not supported", depth));
    WITNESS_CALCULATOR[index].get_or_init(|| {
        let store = Store::default();
        let module = Module::from_binary(&store, WASM[index]).expect("wasm should be valid");
        let result =
            WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
        Mutex::new(result)
    })
}
