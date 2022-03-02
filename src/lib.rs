pub mod hash;
pub mod identity;
pub mod merkle_tree;
pub mod poseidon_tree;
pub mod protocol;
pub mod util;

#[cfg(feature = "mimc")]
pub mod mimc_hash;
#[cfg(feature = "mimc")]
pub mod mimc_tree;

use ark_bn254::Parameters;
use ark_ec::bn::Bn;

pub type Groth16Proof = ark_groth16::Proof<Bn<Parameters>>;
pub type EthereumGroth16Proof = ark_circom::ethereum::Proof;

#[cfg(test)]
mod test {
    use super::*;
    use hash::*;
    use hex_literal::hex;
    use identity::*;
    use poseidon_tree::*;
    use protocol::*;

    #[test]
    fn test_end_to_end() {
        // generate identity
        let id = Identity::new(b"hello");

        // generate merkle tree
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        let mut tree = PoseidonTree::new(21, LEAF);
        let (_, leaf) = id.commitment().to_bytes_be();
        tree.set(0, leaf.into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root();

        // change signal and external_nullifier here
        let signal = "xxx".as_bytes();
        let external_nullifier = "appId".as_bytes();

        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier);

        let config = SnarkFileConfig {
            zkey: "./snarkfiles/semaphore.zkey".to_string(),
            wasm: "./snarkfiles/semaphore.wasm".to_string(),
        };

        let proof =
            generate_proof(&config, &id, &merkle_proof, external_nullifier, signal).unwrap();
        let success = verify_proof(
            &config,
            &root.into(),
            &nullifier_hash,
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
        // Create tree
        let id = Identity::new(b"hello");
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
        let mut tree = PoseidonTree::new(21, LEAF);
        let (_, leaf) = id.commitment().to_bytes_be();
        tree.set(0, leaf.into());
        let merkle_proof = tree.proof(0).expect("proof should exist");

        // change signal and external_nullifier here
        let signal = "xxx".as_bytes();
        let external_nullifier = "appId".as_bytes();

        let config = SnarkFileConfig {
            zkey: "./snarkfiles/semaphore.zkey".to_string(),
            wasm: "./snarkfiles/semaphore.wasm".to_string(),
        };

        criterion.bench_function("proof", move |b| {
            b.iter(|| {
                generate_proof(&config, &id, &merkle_proof, external_nullifier, signal).unwrap();
            })
        });
    }
}
