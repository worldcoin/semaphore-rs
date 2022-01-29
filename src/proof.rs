use ark_circom::{CircomConfig, CircomBuilder};
use ark_std::rand::thread_rng;
use ark_bn254::Bn254;
use color_eyre::Result;
use num_bigint::BigInt;

use crate::{identity::*, poseidon_tree::{Proof}, merkle_tree::Branch};

use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
};

// fn to_array32(s: &BigInt, size: usize) -> Vec<i32> {
//     let mut res = vec![0; size as usize];
//     let mut rem = s.clone();
//     let radix = BigInt::from(0x100000000u64);
//     let mut c = size - 1;
//     while !rem.is_zero() {
//         !dbg(&rem);
//         !dbg(&radix);
//         !dbg((&rem % &radix));
//         res[c] = (&rem % &radix).to_i32().unwrap();
//         rem /= &radix;
//         c -= 1;
//     }

//     res
// }

// WIP: uses dummy proofs for now
pub fn proof_signal(identity: &Identity, proof: &Proof) -> Result<()> {

    // TODO: we should create a From trait for this
    let proof = proof.0.iter().map(|x| {
        match x {
            Branch::Left(value) => value.into(),
            Branch::Right(value) => value.into(),
        }
    }).collect::<Vec<BigInt>>();

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

    let tmp = BigInt::parse_bytes(
        b"4344141139294650952352150677542411196253771789435022697920397562624821372579",
        10,
    )
    .unwrap();
    builder.push_input("identity_nullifier", tmp);

    // dbg!(&tmp % BigInt::from(0x100000000u64));
    // builder.push_input("identity_trapdoor", BigInt::parse_bytes(
    //     b"57215223214535428002775309386374815284773502419290683020798284477163412139477",
    //     10,
    // )
    // .unwrap());

    // // TODO: calculate vec
    // builder.push_input("identity_path_index", BigInt::from(0 as i32));
    // builder.push_input("identity_path_index", BigInt::from(0 as i32));

    // for el in proof {
    //     builder.push_input("path_elements", el);
    // }

    // builder.push_input("external_nullifier", BigInt::from(123 as i32));
    // builder.push_input("signal_hash", BigInt::parse_bytes(
    //     b"426814738191208581806614072441429636075448095566621754358249936829881365458n",
    //     10,
    // )
    // .unwrap());

    // builder.push_input("nullifierHash", BigInt::from(0 as i32));
    // builder.push_input("root", BigInt::from(0 as i32));

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

