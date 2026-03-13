use crate::{
    identity::Identity,
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

#[cfg(test)]
mod tests {
    use semaphore_rs_depth_macros::test_all_depths;

    use crate::{hash_to_field, identity::Identity, protocol::generate_nullifier_hash};

    use super::*;

    #[test_all_depths]
    fn test_round_trip(depth: usize) {
        let mut secret = *b"test secret seed";
        let id = Identity::from_secret(&mut secret, None);

        let signal_hash = hash_to_field(b"signal");
        let external_nullifier_hash = hash_to_field(b"app_id");
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        let proof = generate_proof(depth, &id, external_nullifier_hash, signal_hash)
            .expect("proof generation should succeed");

        let valid = verify_proof(
            depth,
            id.commitment(),
            nullifier_hash,
            signal_hash,
            external_nullifier_hash,
            &proof,
        )
        .expect("proof verification should succeed");

        assert!(valid);
    }
}
