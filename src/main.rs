mod hash;
mod identity;
mod merkle_tree;
mod poseidon_tree;
mod protocol;
mod util;

use hex_literal::hex;
use num_bigint::BigInt;
use poseidon_rs::Poseidon;
use {hash::*, identity::*, poseidon_tree::*, protocol::*};

fn main() {
    // generate identity
    let id = Identity::new(b"hello");
    dbg!(&id);

    // generate merkle tree
    const LEAF: Hash = Hash::from_bytes_be(hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ));

    let mut tree = PoseidonTree::new(21, LEAF);
    let (_, leaf) = id.identity_commitment().to_bytes_be();
    tree.set(0, leaf.into());

    let root: BigInt = tree.root().into();
    dbg!(root);

    let merkle_proof = tree.proof(0).expect("proof should exist");
    let root = tree.root().into();

    let signal = b"xxx";
    let external_nullifier = BigInt::from(123 as i32);
    let nullifier_hash = generate_nullifier_hash(&external_nullifier, &id.nullifier);

    let proof = generate_proof(&id, &merkle_proof, &external_nullifier, &signal[..]).unwrap();
    let res = verify_proof(&root, &nullifier_hash, &signal[..], &external_nullifier, &proof).unwrap();

    dbg!(res);
}
