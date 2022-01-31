mod proof;
mod identity;
mod merkle_tree;
mod poseidon_tree;
mod hash;

use num_bigint::BigInt;
use poseidon_rs::Poseidon;
use hex_literal::hex;
use {identity::*, poseidon_tree::*, hash::*, proof::*};

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

    let (_, leaf) = id.identity_commitment().to_bytes_be();
    dbg!(&leaf);

    tree.set(2, leaf.into());

    let root: BigInt = tree.root().into();
    dbg!(root);

    let proof = tree.proof(2).expect("proof should exist");

    dbg!(proof.path_index());

    // let proof: Vec<BigInt> = proof.0.iter().map(|x| {
    //     match x {
    //         Branch::Left(value) => value.into(),
    //         Branch::Right(value) => value.into(),
    //     }
    // }).collect();

    // dbg!(proof);

    proof_signal(&id, &proof);

}
