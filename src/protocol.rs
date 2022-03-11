use crate::{
    identity::Identity,
    merkle_tree::{self, Branch},
    poseidon_tree::PoseidonHash,
    posseidon_hash, Field,
};
use ark_bn254::{Bn254, Parameters};
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_ec::bn::Bn;
use ark_ff::{Fp256, PrimeField};
use ark_groth16::{create_proof_with_reduction_and_matrices, prepare_verifying_key, Proof};
use ark_relations::r1cs::SynthesisError;
use ark_std::{rand::thread_rng, UniformRand};
use color_eyre::Result;
use ethers_core::utils::keccak256;
use std::{collections::HashMap, fs::File, ops::Shr, time::Instant};
use thiserror::Error;

pub struct SnarkFileConfig {
    pub zkey: String,
    pub wasm: String,
}

/// Helper to merkle proof into a bigint vector
/// TODO: we should create a From trait for this
fn merkle_proof_to_vec(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<Field> {
    proof
        .0
        .iter()
        .map(|x| match x {
            Branch::Left(value) | Branch::Right(value) => value.into(),
        })
        .collect()
}

/// Internal helper to hash the signal to make sure it's in the field
fn hash_signal(signal: &[u8]) -> Field {
    todo!()
    // BigInt::from_bytes_be(Sign::Plus, &keccak256(signal)).shr(8)
}

/// Internal helper to hash the external nullifier
#[must_use]
pub fn hash_external_nullifier(nullifier: &[u8]) -> Field {
    // Hash input to 256 bits.
    let mut hash = keccak256(nullifier);
    // Clear first four bytes to make sure the hash is in the field.
    for byte in &mut hash[0..4] {
        *byte = 0;
    }
    // Convert to field element.
    Fp256::from_be_bytes_mod_order(&hash)
}

/// Generates the nullifier hash
#[must_use]
pub fn generate_nullifier_hash(identity: &Identity, external_nullifier: Field) -> Field {
    posseidon_hash(&[external_nullifier, identity.nullifier])
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Error reading circuit key: {0}")]
    CircuitKeyError(#[from] std::io::Error),
    #[error("Error producing witness: {0}")]
    WitnessError(color_eyre::Report),
    #[error("Error producing proof: {0}")]
    SynthesisError(#[from] SynthesisError),
}

fn ark_to_bigint(n: Field) -> num_bigint::BigInt {
    todo!()
}

/// Generates a semaphore proof
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof(
    config: &SnarkFileConfig,
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier: &[u8],
    signal: &[u8],
) -> Result<Proof<Bn<Parameters>>, ProofError> {
    let mut file = File::open(&config.zkey)?;
    let (params, matrices) = read_zkey(&mut file)?;
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let external_nullifier = hash_external_nullifier(external_nullifier);
    let signal = hash_signal(signal);
    let inputs = [
        ("identityNullifier", vec![identity.nullifier]),
        ("identityTrapdoor", vec![identity.trapdoor]),
        ("treePathIndices", merkle_proof.path_index()),
        ("treeSiblings", merkle_proof_to_vec(merkle_proof)),
        ("externalNullifier", vec![external_nullifier]),
        ("signalHash", vec![signal]),
    ];
    let inputs = inputs.iter().map(|(name, values)| {
        (
            name.to_string(),
            values
                .iter()
                .copied()
                .map(ark_to_bigint)
                .collect::<Vec<_>>(),
        )
    });

    let now = Instant::now();

    let mut witness = WitnessCalculator::new(&config.wasm).map_err(ProofError::WitnessError)?;

    let full_assignment = witness
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(ProofError::WitnessError)?;

    println!("witness generation took: {:.2?}", now.elapsed());

    let mut rng = thread_rng();
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
    )?;

    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

/// Verifies a given semaphore proof
///
/// # Errors
///
/// Returns a [`ProofError`] if verifying fails. Verification failure does not
/// necessarily mean the proof is incorrect.
pub fn verify_proof(
    config: &SnarkFileConfig,
    root: Field,
    nullifier_hash: Field,
    signal: &[u8],
    external_nullifier: &[u8],
    proof: &Proof<Bn<Parameters>>,
) -> Result<bool, ProofError> {
    let mut file = File::open(&config.zkey)?;
    let (params, _) = read_zkey(&mut file)?;

    let pvk = prepare_verifying_key(&params.vk);

    let public_inputs = vec![
        root,
        nullifier_hash,
        hash_signal(signal),
        hash_external_nullifier(external_nullifier),
    ];
    let result = ark_groth16::verify_proof(&pvk, proof, &public_inputs)?;
    Ok(result)
}
