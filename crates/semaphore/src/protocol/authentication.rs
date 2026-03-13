use crate::{
    identity::Identity,
    // PoseidonTree = semaphore_rs_trees::imt::MerkleTree<Poseidon> — a plain
    // Vec-backed incremental Merkle tree that works on all targets including
    // wasm32 (no mmap dependency).
    poseidon_tree::PoseidonTree,
    protocol::{Proof, ProofError},
    Field,
};

pub fn generate_proof(
    depth: usize,
    identity: &Identity,
    ext_nullifier_hash: Field,
    signal_hash: Field,
) -> Result<Proof, ProofError> {
    let mut tree = PoseidonTree::new(depth, Field::from(0));
    tree.set(0, identity.commitment());
    // proof(0) always returns Some: leaf 0 < 2^depth for any usize depth
    let merkle_proof = tree.proof(0).expect("leaf index 0 is always in-bounds");
    super::generate_proof(identity, &merkle_proof, ext_nullifier_hash, signal_hash)
}

pub fn verify_proof(
    depth: usize,
    id_commitment: Field,
    nullifier_hash: Field,
    signal_hash: Field,
    ext_nullifier_hash: Field,
    proof: &Proof,
) -> Result<bool, ProofError> {
    let mut tree = PoseidonTree::new(depth, Field::from(0));
    tree.set(0, id_commitment);
    let root = tree.root();
    super::verify_proof(
        root,
        nullifier_hash,
        signal_hash,
        ext_nullifier_hash,
        proof,
        depth,
    )
}
