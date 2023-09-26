use crate::{
    identity::Identity,
    poseidon_tree::LazyPoseidonTree,
    protocol::{Proof, ProofError},
    Field,
};

pub fn generate_proof(
    depth: usize,
    identity: &Identity,
    ext_nullifier_hash: Field,
    signal_hash: Field,
) -> Result<Proof, ProofError> {
    let merkle_proof = LazyPoseidonTree::new(depth, Field::from(0))
        .update(0, &identity.commitment())
        .proof(0);
    return super::generate_proof(identity, &merkle_proof, ext_nullifier_hash, signal_hash);
}

pub fn verify_proof(
    depth: usize,
    id_commitment: Field,
    nullifier_hash: Field,
    signal_hash: Field,
    ext_nullifier_hash: Field,
    proof: &Proof,
) -> Result<bool, ProofError> {
    let root = LazyPoseidonTree::new(depth, Field::from(0))
        .update(0, &id_commitment)
        .root();
    return super::verify_proof(
        root,
        nullifier_hash,
        signal_hash,
        ext_nullifier_hash,
        proof,
        depth,
    );
}
