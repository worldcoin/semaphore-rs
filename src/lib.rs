#![doc = include_str!("../README.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
// TODO: ark-circom and ethers-core pull in a lot of dependencies, some duplicate.
#![allow(clippy::multiple_crate_versions)]

pub mod circuit;
mod field;
pub mod hash;
pub mod identity;
pub mod merkle_tree;
mod poseidon_hash;
pub mod poseidon_tree;
pub mod protocol;
pub mod util;

#[cfg(feature = "mimc")]
pub mod mimc_hash;
#[cfg(feature = "mimc")]
pub mod mimc_tree;

use ark_bn254::Parameters;
use ark_ec::bn::Bn;

// Export types
pub use crate::{
    field::{hash_to_field, Field},
    poseidon_hash::poseidon_hash,
};

pub type Groth16Proof = ark_groth16::Proof<Bn<Parameters>>;
pub type EthereumGroth16Proof = ark_circom::ethereum::Proof;

#[cfg(test)]
mod test {
    use crate::{
        hash_to_field,
        identity::Identity,
        poseidon_tree::PoseidonTree,
        protocol::{generate_nullifier_hash, generate_proof, verify_proof},
        Field,
    };
    use std::thread::spawn;

    #[test]
    fn test_field_serde() {
        let value = Field::from(0x1234_5678);
        let serialized = serde_json::to_value(value).unwrap();
        let deserialized = serde_json::from_value(serialized).unwrap();
        assert_eq!(value, deserialized);
    }

    fn test_end_to_end(identity: &[u8], external_nullifier: &[u8], signal: &[u8]) {
        // const LEAF: Hash = Hash::from_bytes_be(hex!(
        //     "0000000000000000000000000000000000000000000000000000000000000000"
        // ));
        let leaf = Field::from(0);

        // generate identity
        let id = Identity::from_seed(identity);

        // generate merkle tree
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root();
        dbg!(root);

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
            )
            .unwrap();
            assert!(success);
        }
    }
    #[test]
    fn test_single() {
        // Note that rust will still run tests in parallel
        test_end_to_end(b"hello", b"appId", b"xxx");
    }

    #[test]
    fn test_parallel() {
        // Note that this does not guarantee a concurrency issue will be detected.
        // For that we need much more sophisticated static analysis tooling like
        // loom. See <https://github.com/tokio-rs/loom>
        let a = spawn(|| test_end_to_end(b"hello", b"appId", b"xxx"));
        let b = spawn(|| test_end_to_end(b"secret", b"test", b"signal"));
        a.join().unwrap();
        b.join().unwrap();
    }
}

#[cfg(feature = "bench")]
pub mod bench {
    use crate::{
        hash_to_field, identity::Identity, poseidon_tree::PoseidonTree, protocol::generate_proof,
        Field,
    };
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        #[cfg(feature = "mimc")]
        crate::mimc_hash::bench::group(criterion);
        #[cfg(feature = "mimc")]
        crate::mimc_tree::bench::group(criterion);
        bench_proof(criterion);
    }

    fn bench_proof(criterion: &mut Criterion) {
        let leaf = Field::from(0);

        // Create tree
        let id = Identity::from_seed(b"hello");
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment());
        let merkle_proof = tree.proof(0).expect("proof should exist");

        // change signal and external_nullifier here
        let signal_hash = hash_to_field(b"xxx");
        let external_nullifier_hash = hash_to_field(b"appId");

        criterion.bench_function("proof", move |b| {
            b.iter(|| {
                generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();
            });
        });
    }
}
