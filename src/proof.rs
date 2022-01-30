use ark_circom::{CircomConfig, CircomBuilder, read_zkey, WitnessCalculator, CircomReduction};
use ark_std::rand::thread_rng;
use ark_bn254::Bn254;
use color_eyre::Result;
use num_bigint::BigInt;

use std::{collections::HashMap, fs::File};

use crate::{identity::*, poseidon_tree::{Proof}, merkle_tree::Branch};

use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof, create_proof_with_reduction_and_matrices,
};

// WIP: uses dummy proofs for now
pub fn proof_signal(identity: &Identity, proof: &Proof) -> Result<()> {

    // TODO: we should create a From trait for this
    let proof = proof.0.iter().map(|x| {
        match x {
            Branch::Left(value) => value.into(),
            Branch::Right(value) => value.into(),
        }
    }).collect::<Vec<BigInt>>();

    let mut file = File::open("./snarkfiles/semaphore.zkey").unwrap();
    let (params, matrices) = read_zkey(&mut file).unwrap();
    let num_inputs = matrices.num_instance_variables;
    let num_constraints = matrices.num_constraints;

    let inputs = {
        let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();

        let values = inputs.entry("identity_nullifier".to_string()).or_insert_with(Vec::new);
        values.push(BigInt::parse_bytes(
            b"4344141139294650952352150677542411196253771789435022697920397562624821372579",
            10,
        )
        .unwrap());

        //

        let values = inputs.entry("identity_trapdoor".to_string()).or_insert_with(Vec::new);
        values.push(BigInt::parse_bytes(
            b"57215223214535428002775309386374815284773502419290683020798284477163412139477",
            10,
        )
        .unwrap());

        //

        let values = inputs.entry("identity_path_index".to_string()).or_insert_with(Vec::new);
        values.push(BigInt::from(0 as i32));
        values.push(BigInt::from(0 as i32));

        //
        let values = inputs.entry("path_elements".to_string()).or_insert_with(Vec::new);
        for el in proof {
            values.push(el);
        }

        //

        let values = inputs.entry("external_nullifier".to_string()).or_insert_with(Vec::new);
        values.push(BigInt::from(123 as i32));

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

