pub mod hash;
pub mod identity;
pub mod merkle_tree;
pub mod poseidon_tree;
pub mod protocol;
pub mod util;

use ark_bn254::Parameters;
use ark_ec::bn::Bn;
use ark_groth16::Proof;

pub type Groth16Proof = Proof<Bn<Parameters>>;