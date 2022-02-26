mod hash;
mod identity;
mod merkle_tree;
mod poseidon_tree;
mod protocol;
mod util;

use hash::*;
use hex_literal::hex;
use identity::*;
use num_bigint::{BigInt};
use poseidon_tree::*;
use protocol::*;

fn main() {
    // generate identity
    let id = Identity::new(b"hello");
    dbg!(&id);
    dbg!(id.commitment());

    // generate merkle tree
    const LEAF: Hash = Hash::from_bytes_be(hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ));

    let mut tree = PoseidonTree::new(21, LEAF);
    let (_, leaf) = id.commitment().to_bytes_be();
    tree.set(0, leaf.into());

    let root: BigInt = tree.root().into();
    dbg!(root);

    let merkle_proof = tree.proof(0).expect("proof should exist");
    let root = tree.root().into();

    // change signal and external_nullifier here
    let signal = "xxx".as_bytes();
    let external_nullifier = "appId".as_bytes();

    let nullifier_hash = generate_nullifier_hash(&id, external_nullifier);
    dbg!(&nullifier_hash);

    let config = SnarkFileConfig {
        zkey: "./snarkfiles/semaphore.zkey".to_string(),
        wasm: "./snarkfiles/semaphore.wasm".to_string(),
    };

    let proof = generate_proof(&config, &id, &merkle_proof, external_nullifier, signal).unwrap();
    let success = verify_proof(
        &config,
        &root,
        &nullifier_hash,
        signal,
        external_nullifier,
        &proof,
    )
    .unwrap();

    dbg!(success);
}
