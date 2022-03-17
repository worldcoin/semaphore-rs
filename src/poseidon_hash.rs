use crate::Field;
use once_cell::sync::Lazy;
use poseidon_rs::Poseidon;

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

#[must_use]
pub fn poseidon_hash(input: &[Field]) -> Field {
    let input = input.iter().copied().map(Into::into).collect::<Vec<_>>();

    POSEIDON
        .hash(input)
        .map(Into::into)
        .expect("hash with fixed input size can't fail")
}
