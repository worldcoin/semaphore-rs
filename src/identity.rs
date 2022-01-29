use color_eyre::Result;
use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::{BigInt, Sign};
use once_cell::sync::Lazy;
use poseidon_rs::{Fr, FrRepr, Poseidon};
use sha2::{Digest, Sha256};

use crate::{hash::Hash};

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

fn bigint_to_fr(bi: &BigInt) -> Fr {
    // dirty: have to force the point into the field manually, otherwise you get an error if bi not in field
    let q = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();
    let m = bi.modpow(&BigInt::from(1), &q);

    let mut repr = FrRepr::default();
    let (_, res) = m.to_bytes_be();
    repr.read_be(&res[..]).unwrap();
    Fr::from_repr(repr).unwrap()
}

fn fr_to_bigint(fr: Fr) -> BigInt {
    let mut bytes = [0_u8; 32];
    fr.into_repr().write_be(&mut bytes[..]).unwrap();
    BigInt::from_bytes_be(Sign::Plus, &bytes)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Identity {
    pub identity_trapdoor: BigInt,
    pub identity_nullifier: BigInt,
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
        let identity_trapdoor = BigInt::from_bytes_be(
            Sign::Plus,
            &sha(format!("{}identity_trapdoor", hex::encode(seed_hash)).as_bytes()),
        );
        let identity_nullifier = BigInt::from_bytes_be(
            Sign::Plus,
            &sha(format!("{}identity_nullifier", hex::encode(seed_hash)).as_bytes()),
        );

        Self {
            identity_trapdoor,
            identity_nullifier,
        }
    }

    pub fn secret_hash(&self) -> BigInt {
        let res = POSEIDON
            .hash(vec![
                bigint_to_fr(&self.identity_nullifier),
                bigint_to_fr(&self.identity_trapdoor),
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

    pub fn identity_commitment_leaf(&self) -> Hash {
        let res = POSEIDON
            .hash(vec![bigint_to_fr(&self.identity_commitment())])
            .unwrap();

        res.into()
    }
}
