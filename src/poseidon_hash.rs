use crate::Field;
use once_cell::sync::Lazy;
use poseidon_rs::Poseidon;

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

#[must_use]
pub fn poseidon_hash(input: &[Field]) -> Field {
    let input = input.iter().map(Into::into).collect::<Vec<_>>();

    POSEIDON
        .hash(input)
        .map(Into::into)
        .expect("hash with fixed input size can't fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::uint;

    #[test]
    fn test_posseidon() {
        uint! {
            assert_eq!(poseidon_hash(&[0_U256]), 0x2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c_U256);
            assert_eq!(poseidon_hash(&[0_U256, 0_U256]), 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864_U256);
            assert_eq!(poseidon_hash(&[0_U256, 0_U256, 0_U256]), 0x0bc188d27dcceadc1dcfb6af0a7af08fe2864eecec96c5ae7cee6db31ba599aa_U256);            assert_eq!(poseidon_hash(&[
                0x2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c_U256,
                0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864_U256,
                0x0bc188d27dcceadc1dcfb6af0a7af08fe2864eecec96c5ae7cee6db31ba599aa_U256
                ]), 0x03df8bf42efff32cb077098ff8312e1e4c21265f8fba2bd3cb3041dd2470a346_U256);
        }
    }
}
