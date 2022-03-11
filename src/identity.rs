use crate::{posseidon_hash, Field};
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Identity {
    pub trapdoor:  Field,
    pub nullifier: Field,
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
    #[must_use]
    pub fn new(seed: &[u8]) -> Self {
        let seed_hash = &sha(seed);

        // https://github.com/appliedzkp/zk-kit/blob/1ea410456fc2b95877efa7c671bc390ffbfb5d36/packages/identity/src/identity.ts#L58
        let trapdoor = Field::from_be_bytes_mod_order(&sha(format!(
            "{}identity_trapdoor",
            hex::encode(seed_hash)
        )
        .as_bytes()));
        let nullifier = Field::from_be_bytes_mod_order(&sha(format!(
            "{}identity_nullifier",
            hex::encode(seed_hash)
        )
        .as_bytes()));

        Self {
            trapdoor,
            nullifier,
        }
    }

    #[must_use]
    pub fn secret_hash(&self) -> Field {
        posseidon_hash(&[self.nullifier, self.trapdoor])
    }

    #[must_use]
    pub fn commitment(&self) -> Field {
        posseidon_hash(&[self.secret_hash()])
    }
}
