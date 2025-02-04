use super::Proof;
use ark_bn254::Config;
use ark_ec::bn::Bn;
use ark_groth16::Proof as ArkProof;

impl From<ArkProof<Bn<Config>>> for Proof {
    fn from(proof: ArkProof<Bn<Config>>) -> Self {
        let proof = semaphore_rs_ark_circom::ethereum::Proof::from(proof);
        let (a, b, c) = proof.as_tuple();
        Self(a, b, c)
    }
}

impl From<Proof> for ArkProof<Bn<Config>> {
    fn from(proof: Proof) -> Self {
        let eth_proof = semaphore_rs_ark_circom::ethereum::Proof {
            a: semaphore_rs_ark_circom::ethereum::G1 {
                x: proof.0 .0,
                y: proof.0 .1,
            },
            #[rustfmt::skip] // Rustfmt inserts some confusing spaces
            b: semaphore_rs_ark_circom::ethereum::G2 {
                // The order of coefficients is flipped.
                x: [proof.1.0[1], proof.1.0[0]],
                y: [proof.1.1[1], proof.1.1[0]],
            },
            c: semaphore_rs_ark_circom::ethereum::G1 {
                x: proof.2 .0,
                y: proof.2 .1,
            },
        };
        eth_proof.into()
    }
}
