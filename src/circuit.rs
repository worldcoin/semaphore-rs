use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::{Lazy, OnceCell};
use std::{io::Cursor, sync::Mutex};
use wasmer::{Module, Store};

#[cfg(feature = "dylib")]
use std::{env, path::Path};
#[cfg(feature = "dylib")]
use wasmer::Dylib;

const ZKEY_BYTES: &[u8] = include_bytes!(env!("BUILD_RS_ZKEY_FILE"));

#[cfg(not(feature = "dylib"))]
const WASM: &[u8] = include_bytes!(env!("BUILD_RS_WASM_FILE"));

static ZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    let mut reader = Cursor::new(ZKEY_BYTES);
    read_zkey(&mut reader).expect("zkey should be valid")
});

static WITNESS_CALCULATOR: OnceCell<Mutex<WitnessCalculator>> = OnceCell::new();

/// Initialize the library.
#[cfg(feature = "dylib")]
pub fn initialize(dylib_path: &Path) {
    WITNESS_CALCULATOR
        .set(from_dylib(dylib_path))
        .expect("Failed to initialize witness calculator");

    // Force init of ZKEY
    Lazy::force(&ZKEY);
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
pub fn zkey() -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
    &*ZKEY
}

#[cfg(feature = "dylib")]
#[must_use]
pub fn witness_calculator() -> &'static Mutex<WitnessCalculator> {
    WITNESS_CALCULATOR.get_or_init(|| {
        let path = env::var("CIRCUIT_WASM_DYLIB").expect(
            "Semaphore-rs is not initialized. The library needs to be initialized before use when \
             build with the `cdylib` feature. You can initialize by calling `initialize` or \
             seting the `CIRCUIT_WASM_DYLIB` environment variable.",
        );
        from_dylib(&Path::new(&path))
    })
}

#[cfg(not(feature = "dylib"))]
#[must_use]
pub fn witness_calculator() -> &'static Mutex<WitnessCalculator> {
    WITNESS_CALCULATOR.get_or_init(|| {
        let store = Store::default();
        let module = Module::from_binary(&store, WASM).expect("wasm should be valid");
        let result =
            WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
        Mutex::new(result)
    })
}
