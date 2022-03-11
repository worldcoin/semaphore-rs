use crate::{
    hash::Hash,
    merkle_tree::{self, Hasher, MerkleTree},
    Field,
};
use ff::{PrimeField, PrimeFieldRepr};
use once_cell::sync::Lazy;
use poseidon_rs::{Fr, FrRepr, Poseidon};
use serde::{Deserialize, Serialize};

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

fn ark_to_posseidon(n: Field) -> Fr {
    todo!()
}

fn posseidon_to_ark(n: Fr) -> Field {
    todo!()
}

pub fn posseidon_hash(input: &[Field]) -> Field {
    let input = input
        .iter()
        .copied()
        .map(ark_to_posseidon)
        .collect::<Vec<_>>();

    POSEIDON
        .hash(input)
        .map(posseidon_to_ark)
        .expect("hash with fixed input size can't fail")
}

#[cfg(test)]
mod test {
    use ff::{Field, PrimeField, PrimeFieldRepr};
    use poseidon_rs::Fr;

    #[test]
    fn test_modulus_identical() {
        let mut modulus = [0_u8; 32];
        let writer = Fr::char().write_be(&mut modulus[..]).unwrap();

        todo!()
    }
}
