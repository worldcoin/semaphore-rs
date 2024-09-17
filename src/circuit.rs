#![allow(unused)]

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

const ZKEY_BYTES: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_ZKEY_FILE_", depth))));

const WASM: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_WASM_FILE_", depth))));

static ZKEY: [Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)>; get_supported_depth_count()] =
    array_for_depths!(|depth| Lazy::new(|| {
        let mut reader = Cursor::new(ZKEY_BYTES[get_depth_index(depth).unwrap()]);
        read_zkey(&mut reader).expect("zkey should be valid")
    }));

static WITNESS_CALCULATOR: [OnceCell<Mutex<WitnessCalculator>>; get_supported_depth_count()] =
    array_for_depths!(|_depth| OnceCell::new());

#[must_use]
pub fn zkey(depth: usize) -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
    let index = get_depth_index(depth).unwrap_or_else(|| panic!("depth {depth} is not supported"));
    &ZKEY[index]
}

#[must_use]
pub fn witness_calculator(depth: usize) -> &'static Mutex<WitnessCalculator> {
    let index = get_depth_index(depth).unwrap_or_else(|| panic!("depth {depth} is not supported"));
    WITNESS_CALCULATOR[index].get_or_init(|| {
        let store = Store::default();
        let module = Module::from_binary(&store, WASM[index]).expect("wasm should be valid");
        let result =
            WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
        Mutex::new(result)
    })
}
