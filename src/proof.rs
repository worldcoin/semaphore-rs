use ark_circom::{read_zkey, WitnessCalculator, CircomReduction};
use ark_std::rand::thread_rng;
use ark_bn254::Bn254;
use color_eyre::Result;
use num_bigint::BigInt;

use std::{collections::HashMap, fs::File};

use crate::{identity::*, poseidon_tree::{Proof}, merkle_tree::Branch};

use ark_groth16::{
    prepare_verifying_key, verify_proof, create_proof_with_reduction_and_matrices,
};

// TODO: we should create a From trait for this
fn proof_to_vec(proof: &Proof) -> Vec<BigInt> {
    proof.0.iter().map(|x| {
        match x {
            Branch::Left(value) => value.into(),
            Branch::Right(value) => value.into(),
        }
    }).collect::<Vec<BigInt>>()
}

// WIP: uses dummy proofs for now
pub fn proof_signal(identity: &Identity, merkle_proof: &Proof, external_nullifier: BigInt) -> Result<()> {

    let mut file = File::open("./snarkfiles/semaphore.zkey").unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let inputs = {
        let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();

        inputs.insert("identity_nullifier".to_string(), vec![identity.nullifier.clone()]);
        inputs.insert("identity_trapdoor".to_string(), vec![identity.trapdoor.clone()]);
        inputs.insert("identity_path_index".to_string(), merkle_proof.path_index());
        inputs.insert("path_elements".to_string(), proof_to_vec(merkle_proof));
        inputs.insert("external_nullifier".to_string(), vec![external_nullifier]);

        //
         
        let values = inputs.entry("signal_hash".to_string()).or_insert_with(Vec::new);
        values.push(BigInt::parse_bytes(
            b"426814738191208581806614072441429636075448095566621754358249936829881365458",
            10,
        )
        .unwrap());

        inputs
    };

    let mut wtns = WitnessCalculator::new("./snarkfiles/semaphore.wasm")
    .unwrap();

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

