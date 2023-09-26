use crate::{
    circuit::{witness_calculator, zkey},
    identity::Identity,
    merkle_tree::{self, Branch},
    poseidon,
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
use ark_std::UniformRand;
use color_eyre::Result;
use ethers_core::types::U256;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

pub mod authentication;

// Matches the private G1Tup type in ark-circom.
pub type G1 = (U256, U256);

// Matches the private G2Tup type in ark-circom.
pub type G2 = ([U256; 2], [U256; 2]);

/// Wrap a proof object so we have serde support
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof(pub G1, pub G2, pub G1);

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
    poseidon::hash2(external_nullifier, identity.nullifier)
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Error reading circuit key: {0}")]
    CircuitKeyError(#[from] std::io::Error),
    #[error("Error producing witness: {0}")]
    WitnessError(color_eyre::Report),
    #[error("Error producing proof: {0}")]
    SynthesisError(#[from] SynthesisError),
    #[error("Error converting public input: {0}")]
    ToFieldError(#[from] ruint::ToFieldError),
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
    generate_proof_rng(
        identity,
        merkle_proof,
        external_nullifier_hash,
        signal_hash,
        &mut thread_rng(),
    )
}

/// Generates a semaphore proof from entropy
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof_rng(
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier_hash: Field,
    signal_hash: Field,
    rng: &mut impl Rng,
) -> Result<Proof, ProofError> {
    generate_proof_rs(
        identity,
        merkle_proof,
        external_nullifier_hash,
        signal_hash,
        ark_bn254::Fr::rand(rng),
        ark_bn254::Fr::rand(rng),
    )
}

fn generate_proof_rs(
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier_hash: Field,
    signal_hash: Field,
    r: ark_bn254::Fr,
    s: ark_bn254::Fr,
) -> Result<Proof, ProofError> {
    let depth = merkle_proof.0.len();
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
            values.iter().map(Into::into).collect::<Vec<_>>(),
        )
    });

    let now = Instant::now();

    let full_assignment = witness_calculator(depth)
        .lock()
        .expect("witness_calculator mutex should not get poisoned")
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(ProofError::WitnessError)?;

    println!("witness generation took: {:.2?}", now.elapsed());

    let now = Instant::now();
    let zkey = zkey(depth);
    let ark_proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
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
    tree_depth: usize,
) -> Result<bool, ProofError> {
    let zkey = zkey(tree_depth);
    let pvk = prepare_verifying_key(&zkey.0.vk);

    let public_inputs = [root, nullifier_hash, signal_hash, external_nullifier_hash]
        .iter()
        .map(ark_bn254::Fr::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let ark_proof = (*proof).into();
    let result = ark_groth16::verify_proof(&pvk, &ark_proof, &public_inputs[..])?;
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{hash_to_field, poseidon_tree::LazyPoseidonTree};
    use rand::SeedableRng as _;
    use rand_chacha::ChaChaRng;
    use semaphore_depth_macros::test_all_depths;
    use serde_json::json;

    fn arb_proof(seed: u64, depth: usize) -> Proof {
        // Deterministic randomness for testing
        let mut rng = ChaChaRng::seed_from_u64(seed);

        // generate identity
        let mut seed: [u8; 16] = rng.gen();
        let id = Identity::from_secret(seed.as_mut(), None);

        // generate merkle tree
        let leaf = Field::from(0);
        let mut tree = LazyPoseidonTree::new(depth, leaf).derived();
        tree = tree.update(0, &id.commitment());

        let merkle_proof = tree.proof(0);

        let external_nullifier: [u8; 16] = rng.gen();
        let external_nullifier_hash = hash_to_field(&external_nullifier);

        let signal: [u8; 16] = rng.gen();
        let signal_hash = hash_to_field(&signal);

        generate_proof_rng(
            &id,
            &merkle_proof,
            external_nullifier_hash,
            signal_hash,
            &mut rng,
        )
        .unwrap()
    }

    #[test_all_depths]
    fn test_proof_cast_roundtrip(depth: usize) {
        let proof = arb_proof(123, depth);
        let ark_proof: ArkProof<Bn<Parameters>> = proof.into();
        let result: Proof = ark_proof.into();
        assert_eq!(proof, result);
    }

    #[test_all_depths]
    fn test_proof_serialize(depth: usize) {
        let proof = arb_proof(456, depth);
        let json = serde_json::to_value(&proof).unwrap();
        let valid_values = match depth {
            16 => json!([
                [
                    "0xe4267974945a50a541e90a399ed9211752216a3e4e1cefab1f0bcd8925ea56e",
                    "0xdd9ada36c50d3f1bf75abe5c5ad7d0a29355b74fc3f604aa108b8886a6ac7f8"
                ],
                [
                    [
                        "0x1621577ad2f90fe2e7ec6f675751693515c3b7e91ee228f1db47fe3aba7c0450",
                        "0x2b07bc915b377f8c7126c2d46636632cdbcb426b446a06edf3320939ee4e1911"
                    ],
                    [
                        "0xf40e93e057c7521720448b3d443eac36ff48705312181c41bd78981923be41a",
                        "0x9ce138011687b44a08b979a85b3b122e7335254a02d4fbae7b38b57653c7eb0"
                    ]
                ],
                [
                    "0x295b30c0c025a2b176de1220acdb5f95119a8938689d73076f02bb6d01601fbb",
                    "0xc71250468b955584be8769b047f79614df1176a7a64683f14c27889d47e614"
                ]
            ]),
            20 => json!([
                [
                    "0x2296e314c88daf893769f4ed0cad8a7f584b39db6ebd4bba230591b5d78f48b3",
                    "0x2e5d33bf993b8e4aba7c06ee82ff7dd674857b491c46f53eda4365ecbf3e5fde"
                ],
                [
                    [
                        "0x277c239fa1cf9e8a7ca65ef09371bee470aad7936583a0b48e60f6a76f17a97c",
                        "0x2b21c607eff04f704e546451dcd27c5f090639074a54b45e345337e09d0ab3d0"
                    ],
                    [
                        "0x73fde4daa004ecb853159e54b98cdd204e7874008f91581601881c968607451",
                        "0x171ee4d007b9286d91b581f6d38902e5befc3876b96c71bc178b5f5e8dbf1e40"
                    ]
                ],
                [
                    "0x25afbb8fef95d8481e9e49b4a94848473794447d032fdde2cd73a0d6318b6c3c",
                    "0x2a24e19699e2d8495357cf9b65fb215cebbcda2817b1627758a330e57db5c4b9"
                ]
            ]),
            30 => json!([
                [
                    "0x19ded61ab5c58fdb12367526c6bc04b9186d0980c4b6fd48a44093e80f9b4206",
                    "0x2e619a034be10e9aab294f1c77a480378e84782c8519449aef0c8f6952382bda"
                ],
                [
                    [
                        "0x2202954c0cdb43dc240d56c3a60d125dbc676f8d97bfeac5987500eb0ff4b9a1",
                        "0x35f5b9d8bfba1341fe9fabef6f46d242e1b22c4006ed3ae3f240f0409b20799"
                    ],
                    [
                        "0x13ef645aeaffda30d38c1df68d79d9682d3d002a388e5672fe9b9c7f3224acd7",
                        "0x10a45a9a99cfaf9aef84ab40c5fdad411e800e24471f24ec76addb74b9e041af"
                    ]
                ],
                [
                    "0x1f72d009494e8694cf608c54131e7d565625d59e4637ea77cbf2620c719e8c77",
                    "0x19ee17159b599f6f4b2294d4fb29760d2dc1b58adc0519ce546ad274928f6bc4"
                ]
            ]),
            _ => panic!("unexpected depth: {}", depth),
        };
        assert_eq!(json, valid_values);
    }
}
