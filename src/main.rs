mod proof;
mod identity;
mod merkle_tree;
mod poseidon_tree;
mod hash;

use poseidon_rs::Poseidon;
use hex_literal::hex;
use {identity::*, poseidon_tree::*, hash::*};

fn main() {

    // generate identity
    let id = Identity::new(b"hello");
    dbg!(&id);
    dbg!(id.identity_commitment());

    // generate merkle tree
    const LEAF: Hash = Hash::from_bytes_be(hex!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ));

    let mut tree = PoseidonTree::new(3, LEAF);
    tree.set(0, id.identity_commitment_leaf());

    dbg!(tree.root());
    let proof = tree.proof(0).expect("proof should exist");
    dbg!(proof);

    

}
