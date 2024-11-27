use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::field::MODULUS;
use crate::Field;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Identity {
    pub trapdoor: Field,
    pub nullifier: Field,
}

/// Implements the private key derivation function from zk-kit.
///
/// See <https://github.com/appliedzkp/zk-kit/blob/1ea410456fc2b95877efa7c671bc390ffbfb5d36/packages/identity/src/identity.ts#L58>
fn derive_field(seed_hex: &[u8; 64], suffix: &[u8]) -> Field {
    let mut hasher = Sha256::new();
    hasher.update(seed_hex);
    hasher.update(suffix);
    Field::try_from_be_slice(hasher.finalize().as_ref()).unwrap() % MODULUS
}

fn seed_hex(seed: &[u8]) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let bytes: [u8; 32] = hasher.finalize().into();
    let mut result = [0_u8; 64];
    hex::encode_to_slice(bytes, &mut result[..]).expect("output buffer is correctly sized");
    result
}

impl Identity {
    #[must_use]
    #[deprecated(since = "0.2.0", note = "please use `from_secret` instead")]
    pub fn from_seed(seed: &[u8]) -> Self {
        let seed_hex = seed_hex(seed);
        Self {
            trapdoor: derive_field(&seed_hex, b"identity_trapdoor"),
            nullifier: derive_field(&seed_hex, b"identity_nullifier"),
        }
    }

    #[must_use]
    pub fn from_secret(secret: &mut [u8], trapdoor_seed: Option<&[u8]>) -> Self {
        let mut secret_hex = seed_hex(secret);
        secret.zeroize();

        Self::from_hashed_secret(&mut secret_hex, trapdoor_seed)
    }

    #[must_use]
    pub fn from_hashed_secret(secret_hex: &mut [u8; 64], trapdoor_seed: Option<&[u8]>) -> Self {
        let identity = Self {
            trapdoor: derive_field(secret_hex, trapdoor_seed.unwrap_or(b"identity_trapdoor")),
            nullifier: derive_field(secret_hex, b"identity_nullifier"),
        };
        secret_hex.zeroize();
        identity
    }

    #[must_use]
    pub fn secret_hash(&self) -> Field {
        poseidon::poseidon::hash2(self.nullifier, self.trapdoor)
    }

    #[must_use]
    pub fn commitment(&self) -> Field {
        poseidon::poseidon::hash1(self.secret_hash())
    }
}
