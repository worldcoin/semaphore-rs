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
use ark_groth16::{
    create_proof_with_reduction_and_matrices, prepare_verifying_key, Proof as ArkProof,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::{rand::thread_rng, UniformRand};
use color_eyre::Result;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

// Matches the private G1Tup type in ark-circom.
pub type G1 = (U256, U256);

// Matches the private G2Tup type in ark-circom.
pub type G2 = ([U256; 2], [U256; 2]);

/// Wrap a proof object so we have serde support
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof(G1, G2, G1);

impl From<ArkProof<Bn<Parameters>>> for Proof {
    fn from(proof: ArkProof<Bn<Parameters>>) -> Self {
        let proof = ark_circom::ethereum::Proof::from(proof);
        let (a, b, c) = proof.as_tuple();
        Self(a, b, c)
    }
}

impl From<Proof> for ArkProof<Bn<Parameters>> {
    fn from(proof: Proof) -> Self {
        let eth_proof = ark_circom::ethereum::Proof {
            a: ark_circom::ethereum::G1 {
                x: proof.0 .0,
                y: proof.0 .1,
            },
            #[rustfmt::skip] // Rustfmt inserts some confusing spaces
            b: ark_circom::ethereum::G2 {
                // The order of coefficients is flipped.
                x: [proof.1.0[1], proof.1.0[0]],
                y: [proof.1.1[1], proof.1.1[0]],
            },
            c: ark_circom::ethereum::G1 {
                x: proof.2 .0,
                y: proof.2 .1,
            },
        };
        eth_proof.into()
    }
}

/// Helper to merkle proof into a bigint vector
/// TODO: we should create a From trait for this
fn merkle_proof_to_vec(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<Field> {
    proof
        .0
        .iter()
        .map(|x| match x {
            Branch::Left(value) | Branch::Right(value) => *value,
        })
        .collect()
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
) -> Result<Proof, ProofError> {
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
            values.iter().copied().map(Into::into).collect::<Vec<_>>(),
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

    let ark_proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &ZKEY.0,
        r,
        s,
        &ZKEY.1,
        ZKEY.1.num_instance_variables,
        ZKEY.1.num_constraints,
        full_assignment.as_slice(),
    )?;
    let proof = ark_proof.into();

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
    proof: &Proof,
) -> Result<bool, ProofError> {
    let pvk = prepare_verifying_key(&ZKEY.0.vk);

    let public_inputs = [
        root.into(),
        nullifier_hash.into(),
        signal_hash.into(),
        external_nullifier_hash.into(),
    ];
    let ark_proof = (*proof).into();
    let result = ark_groth16::verify_proof(&pvk, &ark_proof, &public_inputs[..])?;
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{hash_to_field, poseidon_tree::PoseidonTree};

    #[test]
    fn test_proof_serialize() {
        // generate identity
        let id = Identity::from_seed(b"secret");

        // generate merkle tree
        let leaf = Field::from(0);
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment());

        let merkle_proof = tree.proof(0).expect("proof should exist");

        // change signal and external_nullifier here
        let signal_hash = hash_to_field(b"xxx");
        let external_nullifier_hash = hash_to_field(b"appId");

        let proof =
            generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();

        let _json = serde_json::to_value(&proof).unwrap();

        // TODO: Ideally we would check the output against an expected value,
        // but proof generation is non-deterministic (to achieve
        // zero-knowledge) and there's currently no mechanism to make it
        // deterministic for testing purposes.
    }
}
