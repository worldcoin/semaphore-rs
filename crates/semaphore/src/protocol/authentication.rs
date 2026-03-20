use crate::{
    identity::Identity,
    protocol::{Proof, ProofError},
    Field,
};
use semaphore_rs_poseidon::poseidon::hash2;
use semaphore_rs_trees::{Branch, InclusionProof};

fn empty_hashes(depth: usize) -> Vec<Field> {
    let mut empty = Vec::with_capacity(depth);
    let mut hash = Field::from(0);

    for _ in 0..depth {
        empty.push(hash);
        hash = hash2(hash, hash);
    }

    empty
}

fn authentication_merkle_proof(depth: usize) -> InclusionProof<semaphore_rs_poseidon::Poseidon> {
    InclusionProof(empty_hashes(depth).into_iter().map(Branch::Left).collect())
}

fn authentication_root(depth: usize, id_commitment: Field) -> Field {
    empty_hashes(depth).into_iter().fold(id_commitment, hash2)
}

pub fn generate_proof(
    depth: usize,
    identity: &Identity,
    ext_nullifier_hash: Field,
    signal_hash: Field,
) -> Result<Proof, ProofError> {
    let merkle_proof = authentication_merkle_proof(depth);
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
    let root = authentication_root(depth, id_commitment);
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

    /// Validates the generate/verify round-trip for the authentication API.
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
