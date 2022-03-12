use crate::Field;
use ark_ff::{BigInteger256, PrimeField as _};
use ff::PrimeField as _;
use once_cell::sync::Lazy;
use poseidon_rs::{Fr, FrRepr, Poseidon};

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

#[must_use]
fn ark_to_poseidon(n: Field) -> Fr {
    Fr::from_repr(FrRepr(n.into_repr().0)).expect("n is a valid field element")
}

#[must_use]
fn poseidon_to_ark(n: Fr) -> Field {
    Field::from_repr(BigInteger256(n.into_repr().0)).expect("n is a valid field element")
}

#[must_use]
pub fn poseidon_hash(input: &[Field]) -> Field {
    let input = input
        .iter()
        .copied()
        .map(ark_to_poseidon)
        .collect::<Vec<_>>();

    POSEIDON
        .hash(input)
        .map(poseidon_to_ark)
        .expect("hash with fixed input size can't fail")
}

#[cfg(test)]
mod test {
    use super::{ark_to_poseidon, poseidon_to_ark};
    use crate::Field;
    use ark_ff::{Field as _, UniformRand};
    use ff::PrimeField;
    use poseidon_rs::Fr;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_modulus_identical() {
        assert_eq!(Fr::char().0, Field::characteristic());
    }

    #[test]
    fn test_ark_pos_ark_roundtrip() {
        let mut rng = ChaChaRng::seed_from_u64(123);
        for _ in 0..1000 {
            let n = Field::rand(&mut rng);
            let m = poseidon_to_ark(ark_to_poseidon(n));
            assert_eq!(n, m);
        }
    }
}
