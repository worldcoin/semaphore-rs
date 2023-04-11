use ark_bn254::{Bn254, Fr};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::{Lazy, OnceCell};
use sha2::digest::typenum::Mod;
use std::{io::Cursor, sync::Mutex};
use wasmi::Module;

use semaphore_depth_config::{get_depth_index, get_supported_depth_count};
use semaphore_depth_macros::array_for_depths;
#[cfg(feature = "dylib")]
use std::{env, path::Path};

const ZKEY_BYTES: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_ZKEY_FILE_", depth))));

// #[cfg(not(feature = "dylib"))]
const WASM: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_WASM_FILE_", depth))));

static ZKEY: [Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)>; get_supported_depth_count()] =
    array_for_depths!(|depth| Lazy::new(|| {
        let mut reader = Cursor::new(ZKEY_BYTES[get_depth_index(depth).unwrap()]);
        read_zkey(&mut reader).expect("zkey should be valid")
    }));

#[must_use]
pub fn zkey(depth: usize) -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
    let index = get_depth_index(depth).unwrap_or_else(|| panic!("depth {depth} is not supported"));
    &ZKEY[index]
}

// #[cfg(not(feature = "dylib"))]
#[must_use]
pub fn witness_calculator(depth: usize) -> WitnessCalculator {
    let index = get_depth_index(depth).unwrap_or_else(|| panic!("depth {depth} is not supported"));
    let module = Module::from_buffer(WASM[index]).expect("wasm should be valid");
    WitnessCalculator::from_module(module).expect("Failed to create witness calculator")
}
