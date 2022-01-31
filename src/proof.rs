use ark_bn254::Bn254;
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_std::rand::thread_rng;
use color_eyre::Result;
use ethers::utils::keccak256;
use num_bigint::{BigInt, Sign};

use std::{collections::HashMap, fs::File, ops::Shr};

use crate::{identity::*, merkle_tree::Branch, poseidon_tree::Proof};

use ark_groth16::{create_proof_with_reduction_and_matrices, prepare_verifying_key, verify_proof};

// TODO: we should create a From trait for this
fn proof_to_vec(proof: &Proof) -> Vec<BigInt> {
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
pub fn generate(
    identity: &Identity,
    merkle_proof: &Proof,
    external_nullifier: BigInt,
    signal: &[u8],
) -> Result<()> {
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
        inputs.insert("path_elements".to_string(), proof_to_vec(merkle_proof));
        inputs.insert("external_nullifier".to_string(), vec![external_nullifier]);
        inputs.insert("signal_hash".to_string(), vec![hash_signal(signal)]);

        inputs
    };

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
    )
    .unwrap();

    let elapsed = now.elapsed();
    println!("proof generation took: {:.2?}", elapsed);

    dbg!(&proof);

    let pvk = prepare_verifying_key(&params.vk);
    let inputs = &full_assignment[1..num_inputs];
    let verified = verify_proof(&pvk, &proof, inputs).unwrap();

    assert!(verified);

    Ok(())
}
