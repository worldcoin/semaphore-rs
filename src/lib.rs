#![doc = include_str!("../README.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
// TODO: ark-circom and ethers-core pull in a lot of dependencies, some duplicate.
#![allow(clippy::multiple_crate_versions)]

mod circuit;
mod field;
pub mod hash;
pub mod identity;
pub mod merkle_tree;
pub mod poseidon;
pub mod poseidon_tree;
pub mod protocol;
pub mod util;

pub mod lazy_merkle_tree;
#[cfg(feature = "mimc")]
pub mod mimc_hash;
#[cfg(feature = "mimc")]
pub mod mimc_tree;

use ark_bn254::Parameters;
use ark_ec::bn::Bn;

// Export types
pub use crate::field::{hash_to_field, Field};

pub use semaphore_depth_config::get_supported_depths;

pub type Groth16Proof = ark_groth16::Proof<Bn<Parameters>>;
pub type EthereumGroth16Proof = ark_circom::ethereum::Proof;

#[cfg(test)]
mod test {
    use crate::{
        hash_to_field,
        identity::Identity,
        poseidon_tree::LazyPoseidonTree,
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

    fn test_end_to_end(identity: &[u8], external_nullifier: &[u8], signal: &[u8], depth: usize) {
        // const LEAF: Hash = Hash::from_bytes_be(hex!(
        //     "0000000000000000000000000000000000000000000000000000000000000000"
        // ));
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
    fn test_single(depth: usize) {
        // Note that rust will still run tests in parallel
        test_end_to_end(b"hello", b"appId", b"xxx", depth);
    }

    #[test_all_depths]
    fn test_parallel(depth: usize) {
        // Note that this does not guarantee a concurrency issue will be detected.
        // For that we need much more sophisticated static analysis tooling like
        // loom. See <https://github.com/tokio-rs/loom>
        let a = spawn(move || test_end_to_end(b"hello", b"appId", b"xxx", depth));
        let b = spawn(move || test_end_to_end(b"secret", b"test", b"signal", depth));
        a.join().unwrap();
        b.join().unwrap();
    }
}

#[cfg(feature = "bench")]
pub mod bench {
    use crate::{
        hash_to_field, identity::Identity, poseidon_tree::LazyPoseidonTree,
        protocol::generate_proof, Field,
    };
    use criterion::Criterion;
    use semaphore_depth_config::get_supported_depths;

    pub fn group(criterion: &mut Criterion) {
        #[cfg(feature = "mimc")]
        crate::mimc_hash::bench::group(criterion);
        #[cfg(feature = "mimc")]
        crate::mimc_tree::bench::group(criterion);
        for depth in get_supported_depths() {
            bench_proof(criterion, *depth);
        }
    }

    fn bench_proof(criterion: &mut Criterion, depth: usize) {
        let leaf = Field::from(0);

        // Create tree
        let id = Identity::from_secret(b"hello", None);
        let mut tree = LazyPoseidonTree::new(depth, leaf).derived();
        tree = tree.update(0, &id.commitment());
        let merkle_proof = tree.proof(0);

        // change signal and external_nullifier here
        let signal_hash = hash_to_field(b"xxx");
        let external_nullifier_hash = hash_to_field(b"appId");

        criterion.bench_function(&format!("proof_{depth}"), move |b| {
            b.iter(|| {
                generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();
            });
        });
    }
}
