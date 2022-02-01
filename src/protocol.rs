use ark_bn254::{Bn254};
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_ff::{Fp256};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::thread_rng;
use color_eyre::Result;
use ethers::utils::keccak256;
use num_bigint::{BigInt, Sign};
use std::{collections::HashMap, fs::File, ops::Shr};
use ark_groth16::{create_proof_with_reduction_and_matrices, prepare_verifying_key, Proof};

use crate::{identity::*, merkle_tree::{Branch, self}, poseidon_tree::{PoseidonHash}};

// TODO: we should create a From trait for this
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

fn hash_signal(signal: &[u8]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &keccak256(signal)).shr(8)
}

// WIP: uses dummy proofs for now
pub fn generate_proof(
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier: BigInt,
    signal: &[u8],
) -> Result<()> {
// ) -> Result<Proof<Bn<Parameters>>, SynthesisError> {
    let mut file = File::open("./snarkfiles/semaphore.zkey").unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let inputs = {
        let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();

        inputs.insert(
            "identity_nullifier".to_string(),
            vec![identity.nullifier.clone()],
        );
        inputs.insert(
            "identity_trapdoor".to_string(),
            vec![identity.trapdoor.clone()],
        );
        inputs.insert("identity_path_index".to_string(), merkle_proof.path_index());
        inputs.insert("path_elements".to_string(), merkle_proof_to_vec(merkle_proof));
        inputs.insert("external_nullifier".to_string(), vec![external_nullifier]);
        inputs.insert("signal_hash".to_string(), vec![hash_signal(signal)]);

        inputs
    };

    dbg!(&inputs);

    let nullifier = BigInt::parse_bytes(
        b"2073423254391230197488930967618194527029511360562414420050239137722181518699",
        10,
    )
    .unwrap();

    let root = BigInt::parse_bytes(
        b"9194628565321423830640339892337438998798131617576196335312343809896770847079",
        10,
    )
    .unwrap();

    dbg!(nullifier.sign(), root.sign());

    let mut wtns = WitnessCalculator::new("./snarkfiles/semaphore.wasm").unwrap();

    let full_assignment = wtns
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .unwrap();

    let mut rng = thread_rng();
    use ark_std::UniformRand;
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    use std::time::Instant;
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

    let elapsed = now.elapsed();
    println!("proof generation took: {:.2?}", elapsed);

    dbg!(&proof);

    let pvk = prepare_verifying_key(&params.vk);

    let public_inputs = vec![
        Fp256::from(root.to_biguint().unwrap()),
        Fp256::from(nullifier.to_biguint().unwrap()),
        full_assignment[3],
        full_assignment[4]
    ];

    dbg!(&public_inputs);

    let verified = ark_groth16::verify_proof(&pvk, &proof.unwrap(), &public_inputs).unwrap();

    dbg!(verified);

    // proof
    Ok(())
}

// fn verify_proof(nullifier_hash: BigInt, root: BigInt, proof: &Proof<Bn<Parameters>>) -> Result<()> {
//     let mut file = File::open("./snarkfiles/semaphore.zkey").unwrap();
//     let (params, matrices) = read_zkey(&mut file).unwrap();

//     let pvk = prepare_verifying_key(&params.vk);
//     // let inputs = &full_assignment[1..num_inputs];
//     let verified = ark_groth16::verify_proof(&pvk, proof, inputs).unwrap();

//     // assert!(verified);
//     Ok(())
// }
