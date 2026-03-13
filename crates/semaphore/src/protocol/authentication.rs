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
    use crate::{hash_to_field, identity::Identity, protocol::generate_nullifier_hash};

    use super::*;

    /// Validates the generate/verify round-trip for the authentication API.
    ///
    /// We test at depth 16 only: the logic is depth-agnostic and depth-30
    /// proof generation takes >60 s, which blows the CI time budget.
    /// Depth-20 and depth-30 coverage is provided by the existing
    /// `test_auth_flow`, `test_single`, and `test_parallel` integration tests.
    #[test]
    #[cfg(feature = "depth_16")]
    fn test_round_trip() {
        let depth = 16;
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
