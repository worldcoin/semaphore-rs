mod protocol;
mod identity;
mod merkle_tree;
mod poseidon_tree;
mod hash;

use num_bigint::BigInt;
use poseidon_rs::Poseidon;
use hex_literal::hex;
use {identity::*, poseidon_tree::*, hash::*, protocol::*};

fn main() {

    // generate identity
    let id = Identity::new(b"hello");
    dbg!(&id);
    dbg!(id.identity_commitment());

    // generate merkle tree
    const LEAF: Hash = Hash::from_bytes_be(hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ));

    let mut tree = PoseidonTree::new(21, LEAF);

    let (_, leaf) = id.identity_commitment().to_bytes_be();
    dbg!(&leaf);

    tree.set(0, leaf.into());

    let root: BigInt = tree.root().into();
    dbg!(root);

    let proof = tree.proof(0).expect("proof should exist");

    dbg!(&proof);

    dbg!(&proof.path_index());

    generate_proof(&id, &proof, BigInt::from(123), b"xxx");

}
