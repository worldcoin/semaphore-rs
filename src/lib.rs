#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]
// TODO: ark-circom and ethers-core pull in a lot of deps, some duplicate.
#![allow(clippy::multiple_crate_versions)]

mod circuit;
pub mod hash;
pub mod identity;
pub mod merkle_tree;
pub mod poseidon_tree;
mod posseidon_hash;
pub mod protocol;
pub mod util;

#[cfg(feature = "mimc")]
pub mod mimc_hash;
#[cfg(feature = "mimc")]
pub mod mimc_tree;

use ark_bn254::{Fr, FrParameters, Parameters};
use ark_ec::bn::Bn;

pub use crate::posseidon_hash::posseidon_hash;

pub type Field = Fr;
pub type Groth16Proof = ark_groth16::Proof<Bn<Parameters>>;
pub type EthereumGroth16Proof = ark_circom::ethereum::Proof;

#[cfg(test)]
mod test {
    use crate::{
        hash::Hash,
        identity::Identity,
        poseidon_tree::PoseidonTree,
        protocol::{
            generate_nullifier_hash, generate_proof, hash_external_nullifier, verify_proof,
            SnarkFileConfig,
        },
    };
    use hex_literal::hex;

    #[test]
    fn test_end_to_end() {
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        // generate identity
        let id = Identity::new(b"hello");

        // generate merkle tree
        let mut tree = PoseidonTree::new(21, LEAF);
        tree.set(0, id.commitment().into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root().into();

        // change signal and external_nullifier here
        let signal = b"xxx";
        let external_nullifier = b"appId";

        let external_nullifier_hash = hash_external_nullifier(external_nullifier);
        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        let config = SnarkFileConfig {
            zkey: "./semaphore/build/snark/semaphore_final.zkey".to_string(),
            wasm: "./semaphore/build/snark/semaphore.wasm".to_string(),
        };

        let proof =
            generate_proof(&config, &id, &merkle_proof, external_nullifier, signal).unwrap();

        let success = verify_proof(
            &config,
            root,
            nullifier_hash,
            signal,
            external_nullifier,
            &proof,
        )
        .unwrap();

        assert!(success);
    }
}

#[cfg(feature = "bench")]
pub mod bench {
    use crate::{
        hash::Hash,
        identity::Identity,
        poseidon_tree::PoseidonTree,
        protocol::{generate_proof, SnarkFileConfig},
    };
    use criterion::Criterion;
    use hex_literal::hex;

    pub fn group(criterion: &mut Criterion) {
        #[cfg(feature = "mimc")]
        crate::mimc_hash::bench::group(criterion);
        #[cfg(feature = "mimc")]
        crate::mimc_tree::bench::group(criterion);
        bench_proof(criterion);
    }

    fn bench_proof(criterion: &mut Criterion) {
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        // Create tree
        let id = Identity::new(b"hello");
        let mut tree = PoseidonTree::new(21, LEAF);
        tree.set(0, id.commitment().into());
        let merkle_proof = tree.proof(0).expect("proof should exist");

        // change signal and external_nullifier here
        let signal = b"xxx";
        let external_nullifier = b"appId";

        let config = SnarkFileConfig {
            zkey: "./semaphore/build/snark/semaphore_final.zkey".to_string(),
            wasm: "./semaphore/build/snark/semaphore.wasm".to_string(),
        };

        criterion.bench_function("proof", move |b| {
            b.iter(|| {
                generate_proof(&config, &id, &merkle_proof, external_nullifier, signal).unwrap();
            });
        });
    }
}
