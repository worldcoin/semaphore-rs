use crate::{
    circuit::{WITNESS_CALCULATOR, ZKEY},
    identity::Identity,
    merkle_tree::{self, Branch},
    poseidon_hash,
    poseidon_tree::PoseidonHash,
    Field,
};
use ark_bn254::{Bn254, Parameters};
use ark_circom::CircomReduction;
use ark_ec::bn::Bn;
use ark_ff::PrimeField;
use ark_groth16::{create_proof_with_reduction_and_matrices, prepare_verifying_key, Proof};
use ark_relations::r1cs::SynthesisError;
use ark_std::{rand::thread_rng, UniformRand};
use color_eyre::Result;
use ethers_core::utils::keccak256;
use num_bigint::{BigInt, BigUint, ToBigInt};
use std::time::Instant;
use thiserror::Error;

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

/// Hash arbitrary data to a field element.
///
/// This is used to create `signal_hash` and `external_nullifier_hash`.
#[must_use]
pub fn hash_to_field(data: &[u8]) -> Field {
    let hash = keccak256(data);
    // Shift right one byte to make it fit in the field
    let mut bytes = [0_u8; 32];
    bytes[1..].copy_from_slice(&hash[..31]);
    Field::from_be_bytes_mod_order(&bytes)
}

/// Generates the nullifier hash
#[must_use]
pub fn generate_nullifier_hash(identity: &Identity, external_nullifier: Field) -> Field {
    poseidon_hash(&[external_nullifier, identity.nullifier])
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

fn ark_to_bigint(n: Field) -> BigInt {
    let n: BigUint = n.into();
    n.to_bigint().expect("conversion always succeeds for uint")
}

/// Generates a semaphore proof
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof(
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier_hash: Field,
    signal_hash: Field,
) -> Result<Proof<Bn<Parameters>>, ProofError> {
    let inputs = [
        ("identityNullifier", vec![identity.nullifier]),
        ("identityTrapdoor", vec![identity.trapdoor]),
        ("treePathIndices", merkle_proof.path_index()),
        ("treeSiblings", merkle_proof_to_vec(merkle_proof)),
        ("externalNullifier", vec![external_nullifier_hash]),
        ("signalHash", vec![signal_hash]),
    ];
    let inputs = inputs.into_iter().map(|(name, values)| {
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

    let full_assignment = WITNESS_CALCULATOR
        .clone()
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(ProofError::WitnessError)?;

    println!("witness generation took: {:.2?}", now.elapsed());

    let mut rng = thread_rng();
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let now = Instant::now();

    let proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &ZKEY.0,
        r,
        s,
        &ZKEY.1,
        ZKEY.1.num_instance_variables,
        ZKEY.1.num_constraints,
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
    root: Field,
    nullifier_hash: Field,
    signal_hash: Field,
    external_nullifier_hash: Field,
    proof: &Proof<Bn<Parameters>>,
) -> Result<bool, ProofError> {
    let pvk = prepare_verifying_key(&ZKEY.0.vk);

    let public_inputs = vec![root, nullifier_hash, signal_hash, external_nullifier_hash];
    let result = ark_groth16::verify_proof(&pvk, proof, &public_inputs)?;
    Ok(result)
}
