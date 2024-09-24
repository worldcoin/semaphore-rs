#![doc = include_str!("../README.md")]
#![warn(clippy::all, clippy::cargo)]
// TODO: ark-circom and ethers-core pull in a lot of dependencies, some duplicate.
#![allow(clippy::multiple_crate_versions)]

// pub mod cascading_merkle_tree;
mod circuit;
mod field;
// pub mod generic_storage;
pub mod hash;
pub mod identity;
// pub mod lazy_merkle_tree;
// pub mod merkle_tree;
pub mod packed_proof;
// pub mod poseidon;
pub mod poseidon_tree;
pub mod protocol;
pub mod util;

use ark_bn254::Config;
use ark_ec::bn::Bn;

// Export types
pub use crate::field::{hash_to_field, Field};

pub use semaphore_depth_config::get_supported_depths;

pub type Groth16Proof = ark_groth16::Proof<Bn<Config>>;
pub type EthereumGroth16Proof = ark_circom::ethereum::Proof;

#[allow(dead_code)]
#[cfg(test)]
mod test {
    use crate::{
        hash_to_field,
        identity::Identity,
        poseidon_tree::LazyPoseidonTree,
        protocol,
        protocol::{generate_nullifier_hash, generate_proof, verify_proof},
        Field,
    };
    use semaphore_depth_macros::test_all_depths;
    use std::thread::spawn;

    #[test]
    fn test_field_serde() {
        let value = Field::from(0x1234_5678);
        let serialized = serde_json::to_value(value).unwrap();
        let deserialized = serde_json::from_value(serialized).unwrap();
        assert_eq!(value, deserialized);
    }

    fn test_end_to_end(
        identity: &mut [u8],
        external_nullifier: &[u8],
        signal: &[u8],
        depth: usize,
    ) {
        let leaf = Field::from(0);

        // generate identity
        let id = Identity::from_secret(identity, None);

        // generate merkle tree
        let mut tree = LazyPoseidonTree::new(depth, leaf).derived();
        tree = tree.update(0, &id.commitment());

        let merkle_proof = tree.proof(0);
        let root = tree.root();

        let signal_hash = hash_to_field(signal);
        let external_nullifier_hash = hash_to_field(external_nullifier);
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        let proof =
            generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();

        for _ in 0..5 {
            let success = verify_proof(
                root,
                nullifier_hash,
                signal_hash,
                external_nullifier_hash,
                &proof,
                depth,
            )
            .unwrap();
            assert!(success);
        }
    }

    #[test_all_depths]
    fn test_auth_flow(depth: usize) {
        let mut secret = *b"oh so secret";
        let id = Identity::from_secret(&mut secret[..], None);
        let signal_hash = hash_to_field(b"signal");
        let external_nullifier_hash = hash_to_field(b"appId");
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);
        let id_commitment = id.commitment();

        let proof = protocol::authentication::generate_proof(
            depth,
            &id,
            external_nullifier_hash,
            signal_hash,
        )
        .unwrap();

        let success = protocol::authentication::verify_proof(
            depth,
            id_commitment,
            nullifier_hash,
            signal_hash,
            external_nullifier_hash,
            &proof,
        )
        .unwrap();
        assert!(success);
    }

    #[test_all_depths]
    fn test_single(depth: usize) {
        // Note that rust will still run tests in parallel
        let mut hello = *b"hello";
        test_end_to_end(&mut hello, b"appId", b"xxx", depth);
    }

    #[test_all_depths]
    fn test_parallel(depth: usize) {
        // Note that this does not guarantee a concurrency issue will be detected.
        // For that we need much more sophisticated static analysis tooling like
        // loom. See <https://github.com/tokio-rs/loom>
        let mut a_id = *b"hello";
        let mut b_id = *b"secret";
        let a = spawn(move || test_end_to_end(&mut a_id, b"appId", b"xxx", depth));
        let b = spawn(move || test_end_to_end(&mut b_id, b"test", b"signal", depth));
        a.join().unwrap();
        b.join().unwrap();
    }
}
