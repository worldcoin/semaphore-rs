use ark_bn254::{Bn254, Parameters};
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_ec::bn::Bn;
use ark_ff::Fp256;
use ark_groth16::{create_proof_with_reduction_and_matrices, prepare_verifying_key, Proof};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::thread_rng;
use color_eyre::Result;
use ethers_core::utils::keccak256;
use num_bigint::{BigInt, Sign};
use once_cell::sync::Lazy;
use poseidon_rs::Poseidon;
use std::{collections::HashMap, fs::File, ops::Shr};

use crate::{
    identity::*,
    merkle_tree::{self, Branch},
    poseidon_tree::PoseidonHash,
    util::{bigint_to_fr, fr_to_bigint},
};

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

pub struct SnarkFileConfig {
    pub zkey: String,
    pub wasm: String,
}

/// Helper to merkle proof into a bigint vector
/// TODO: we should create a From trait for this
fn merkle_proof_to_vec(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<BigInt> {
    proof
        .0
        .iter()
        .map(|x| match x {
            Branch::Left(value) => value.into(),
            Branch::Right(value) => value.into(),
        })
        .collect::<Vec<BigInt>>()
}

/// Internal helper to hash the signal to make sure it's in the field
fn hash_signal(signal: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &keccak256(signal)).shr(8)
}

/// Internal helper to hash the external nullifier
pub fn hash_external_nullifier(nullifier: &[u8]) -> [u8; 32] {
    let mut hash = keccak256(nullifier);
    hash[0] = 0;
    hash[1] = 0;
    hash[2] = 0;
    hash[3] = 0;
    hash
}

/// Generates the nullifier hash
pub fn generate_nullifier_hash(identity: &Identity, external_nullifier: &[u8]) -> BigInt {
    let res = POSEIDON
        .hash(vec![
            bigint_to_fr(&BigInt::from_bytes_be(
                Sign::Plus,
                external_nullifier,
            )),
            bigint_to_fr(&identity.nullifier),
        ])
        .unwrap();
    fr_to_bigint(res)
}

/// Generates a semaphore proof
pub fn generate_proof(
    config: &SnarkFileConfig,
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier: &[u8],
    signal: &[u8],
) -> Result<Proof<Bn<Parameters>>, SynthesisError> {
    let mut file = File::open(&config.zkey).unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let inputs = {
        let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();

        inputs.insert("identityNullifier".to_string(), vec![identity
            .nullifier
            .clone()]);
        inputs.insert("identityTrapdoor".to_string(), vec![identity
            .trapdoor
            .clone()]);
        inputs.insert("treePathIndices".to_string(), merkle_proof.path_index());
        inputs.insert(
            "treeSiblings".to_string(),
            merkle_proof_to_vec(merkle_proof),
        );
        inputs.insert("externalNullifier".to_string(), vec![
            BigInt::from_bytes_be(Sign::Plus, external_nullifier),
        ]);
        inputs.insert("signalHash".to_string(), vec![hash_signal(signal)]);

        inputs
    };

    use std::time::Instant;
    let now = Instant::now();

    let mut wtns = WitnessCalculator::new(&config.wasm).unwrap();

    let full_assignment = wtns
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .unwrap();

    println!("witness generation took: {:.2?}", now.elapsed());

    let mut rng = thread_rng();
    use ark_std::UniformRand;
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let now = Instant::now();

    let proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &params,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        full_assignment.as_slice(),
    );

    println!("proof generation took: {:.2?}", now.elapsed());

    proof
}

/// Verifies a given semaphore proof
pub fn verify_proof(
    config: &SnarkFileConfig,
    root: &BigInt,
    nullifier_hash: &BigInt,
    signal: &[u8],
    external_nullifier: &[u8],
    proof: &Proof<Bn<Parameters>>,
) -> Result<bool, SynthesisError> {
    let mut file = File::open(&config.zkey).unwrap();
    let (params, _) = read_zkey(&mut file).unwrap();

    let pvk = prepare_verifying_key(&params.vk);

    let public_inputs = vec![
        Fp256::from(root.to_biguint().unwrap()),
        Fp256::from(nullifier_hash.to_biguint().unwrap()),
        Fp256::from(hash_signal(signal).to_biguint().unwrap()),
        Fp256::from(
            BigInt::from_bytes_be(Sign::Plus, external_nullifier)
                .to_biguint()
                .unwrap(),
        ),
    ];
    ark_groth16::verify_proof(&pvk, proof, &public_inputs)
}
