use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::{BigInt, Sign};
use once_cell::sync::Lazy;
use poseidon_rs::{Fr, FrRepr, Poseidon};
use sha2::{Digest, Sha256};

use crate::util::{fr_to_bigint, bigint_to_fr};

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Identity {
    pub trapdoor: BigInt,
    pub nullifier: BigInt,
}

// todo: improve
fn sha(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let result = hasher.finalize();
    let res: [u8; 32] = result.into();
    res
}

impl Identity {
    pub fn new(seed: &[u8]) -> Self {
        let seed_hash = &sha(seed);

        // https://github.com/appliedzkp/zk-kit/blob/1ea410456fc2b95877efa7c671bc390ffbfb5d36/packages/identity/src/identity.ts#L58
        let trapdoor = BigInt::from_bytes_be(
            Sign::Plus,
            &sha(format!("{}identity_trapdoor", hex::encode(seed_hash)).as_bytes()),
        );
        let nullifier = BigInt::from_bytes_be(
            Sign::Plus,
            &sha(format!("{}identity_nullifier", hex::encode(seed_hash)).as_bytes()),
        );

        Self {
            trapdoor,
            nullifier,
        }
    }

    pub fn secret_hash(&self) -> BigInt {
        let res = POSEIDON
            .hash(vec![
                bigint_to_fr(&self.nullifier),
                bigint_to_fr(&self.trapdoor),
            ])
            .unwrap();
        fr_to_bigint(res)
    }

    pub fn identity_commitment(&self) -> BigInt {
        let res = POSEIDON
            .hash(vec![bigint_to_fr(&self.secret_hash())])
            .unwrap();
        fr_to_bigint(res)
    }

}
