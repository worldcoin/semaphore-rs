use ark_circom::{CircomConfig, CircomBuilder};
use ark_std::rand::thread_rng;
use ark_bn254::Bn254;
use color_eyre::Result;

use crate::identity::*;

use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
};

// WIP: uses dummy proofs for now
fn proof_signal(identity: Identity) -> Result<()> {
    let cfg = CircomConfig::<Bn254>::new(
        "./snarkfiles/circom2_multiplier2.wasm",
        "./snarkfiles/circom2_multiplier2.r1cs",
    )?;

    // identity_nullifier: identityNullifier,
    // identity_trapdoor: identityTrapdoor,
    // identity_path_index: merkleProof.pathIndices,
    // path_elements: merkleProof.siblings,
    // external_nullifier: externalNullifier,
    // signal_hash: shouldHash ? genSignalHash(signal) : signal

    let mut builder = CircomBuilder::new(cfg);
    // builder.push_input("a", 3);
    // builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    dbg!(&inputs);

    let proof = prove(circom, &params, &mut rng)?;

    let pvk = prepare_verifying_key(&params.vk);

    let verified = verify_proof(&pvk, &proof, &inputs)?;

    assert!(verified);

    Ok(())
}

