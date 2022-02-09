mod hash;
mod identity;
mod merkle_tree;
mod poseidon_tree;
mod protocol;
mod util;

use ark_bn254::Parameters;
use ark_ec::bn::Bn;
use ark_groth16::Proof;
use hex_literal::hex;
use num_bigint::{BigInt};
use poseidon_tree::PoseidonHash;
use protocol::SnarkFileConfig;
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

use crate::{hash::Hash, poseidon_tree::PoseidonTree};

/// Creates a new idenity and returns the object
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn new_identity(seed: *const c_char) -> *mut identity::Identity {
    let c_str = unsafe { CStr::from_ptr(seed) };
    let seed = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };
    let id = identity::Identity::new(seed.as_bytes());

    let boxed: Box<identity::Identity> = Box::new(id);
    Box::into_raw(boxed)
}

/// Generates the identity commitment based on seed for identity
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn generate_identity_commitment(
    identity: *mut identity::Identity,
) -> *mut c_char {
    let identity = &*identity;
    CString::new(identity.commitment().to_str_radix(10))
        .unwrap()
        .into_raw()
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn generate_nullifier_hash(
    identity: *mut identity::Identity,
    external_nullifier: *const c_char,
) -> *mut c_char {
    let identity = &*identity;

    let c_str = unsafe { CStr::from_ptr(external_nullifier) };
    let external_nullifier = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    CString::new(
        protocol::generate_nullifier_hash(identity, external_nullifier.as_bytes()).to_str_radix(10),
    )
    .unwrap()
    .into_raw()
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn create_poseidon_tree(depth: c_int) -> *mut PoseidonTree {
    const LEAF: Hash = Hash::from_bytes_be(hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ));

    let tree = PoseidonTree::new(depth as usize, LEAF);

    let boxed: Box<PoseidonTree> = Box::new(tree);
    Box::into_raw(boxed)
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn insert_leaf(tree: *mut PoseidonTree, identity: *mut identity::Identity) {
    let identity = &*identity;
    let tree = unsafe {
        assert!(!tree.is_null());
        &mut *tree
    };

    let (_, leaf) = identity.commitment().to_bytes_be();
    tree.set(0, leaf.into());
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn get_root(tree: *mut PoseidonTree) -> *mut c_char {
    let tree = unsafe {
        assert!(!tree.is_null());
        &mut *tree
    };

    let root: BigInt = tree.root().into();
    CString::new(root.to_str_radix(10)).unwrap().into_raw()
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn get_merkle_proof(
    tree: *mut PoseidonTree,
    leaf_idx: c_int,
) -> *mut merkle_tree::Proof<PoseidonHash> {
    let tree = unsafe {
        assert!(!tree.is_null());
        &mut *tree
    };

    let proof = tree.proof(leaf_idx as usize).expect("proof should exist");

    let boxed: Box<merkle_tree::Proof<PoseidonHash>> = Box::new(proof);
    Box::into_raw(boxed)
}

/// Generates nullifier hash based on identity and external nullifier
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn generate_proof(
    identity: *mut identity::Identity,
    external_nullifier: *const c_char,
    signal: *const c_char,
    merkle_proof: *mut merkle_tree::Proof<PoseidonHash>,
    zkey_path: *const c_char,
    wasm_path: *const c_char,
) -> *mut Proof<Bn<Parameters>> {
    let c_str = unsafe { CStr::from_ptr(external_nullifier) };
    let external_nullifier = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(signal) };
    let signal = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(zkey_path) };
    let zkey_path = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(wasm_path) };
    let wasm_path = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let config = SnarkFileConfig {
        zkey: zkey_path.to_string(),
        wasm: wasm_path.to_string(),
    };

    let identity = &*identity;
    let merkle_proof = &*merkle_proof;

    let res = protocol::generate_proof(
        &config,
        identity,
        merkle_proof,
        external_nullifier.as_bytes(),
        signal.as_bytes(),
    );

    let boxed: Box<Proof<Bn<Parameters>>> = Box::new(res.unwrap());
    Box::into_raw(boxed)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn verify_proof(
    root: *const c_char,
    external_nullifier: *const c_char,
    signal: *const c_char,
    nullifier: *const c_char,
    proof: *mut Proof<Bn<Parameters>>,
    zkey_path: *const c_char,
    wasm_path: *const c_char,
) -> c_int {
    let c_str = unsafe { CStr::from_ptr(root) };
    let root = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(external_nullifier) };
    let external_nullifier = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(signal) };
    let signal = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(nullifier) };
    let nullifier = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(zkey_path) };
    let zkey_path = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(wasm_path) };
    let wasm_path = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let config = SnarkFileConfig {
        zkey: zkey_path.to_string(),
        wasm: wasm_path.to_string(),
    };

    let proof = &*proof;

    let root = BigInt::parse_bytes(root.as_bytes(), 10).unwrap();
    let nullifier = BigInt::parse_bytes(nullifier.as_bytes(), 10).unwrap();

    protocol::verify_proof(
        &config,
        &root,
        &nullifier, 
        signal.as_bytes(),
        external_nullifier.as_bytes(),
        proof,
    )
    .unwrap() as i32
}
