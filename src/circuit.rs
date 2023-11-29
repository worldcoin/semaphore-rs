#![allow(unused)]

use ark_bn254::{Bn254, Fr};
use ark_circom::read_zkey;
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use once_cell::sync::Lazy;
use std::io::Cursor;

use ark_zkey;
use semaphore_depth_config::{get_depth_index, get_supported_depth_count};
use semaphore_depth_macros::array_for_depths;

const ZKEY_BYTES: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_ARKZKEY_FILE_", depth))));

const GRAPH_BYTES: [&[u8]; get_supported_depth_count()] =
    array_for_depths!(|depth| include_bytes!(env!(concat!("BUILD_RS_GRAPH_FILE_", depth))));

static ZKEY: [Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)>; get_supported_depth_count()] =
    array_for_depths!(|depth| Lazy::new(|| {
        let mut reader = Cursor::new(ZKEY_BYTES[get_depth_index(depth).unwrap()]);
        ark_zkey::read_arkzkey(&mut reader).expect("zkey should be valid")
    }));

#[must_use]
pub fn zkey(depth: usize) -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
    let index = get_depth_index(depth).unwrap_or_else(|| panic!("depth {depth} is not supported"));
    &ZKEY[index]
}

#[must_use]
pub fn graph(depth: usize) -> &'static [u8] {
    let index = get_depth_index(depth).unwrap_or_else(|| panic!("depth {depth} is not supported"));
    &GRAPH_BYTES[index]
}
