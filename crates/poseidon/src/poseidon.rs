use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use once_cell::sync::Lazy;
use ruint::aliases::U256;

use crate::constants;

static M1: Lazy<[[Fr; 2]; 2]> = Lazy::new(|| {
    constants::M1
        .iter()
        .map(|row| {
            row.iter()
                .map(Fr::try_from)
                .collect::<Result<Vec<Fr>, _>>()
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<[Fr; 2]>>()
        .try_into()
        .unwrap()
});

static C1: Lazy<[[Fr; 2]; 64]> = Lazy::new(|| {
    constants::C1
        .iter()
        .map(|row| {
            row.iter()
                .map(Fr::try_from)
                .collect::<Result<Vec<Fr>, _>>()
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<[Fr; 2]>>()
        .try_into()
        .unwrap()
});

static M: Lazy<[[Fr; 3]; 3]> = Lazy::new(|| {
    constants::M
        .iter()
        .map(|row| {
            row.iter()
                .map(Fr::try_from)
                .collect::<Result<Vec<Fr>, _>>()
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<[Fr; 3]>>()
        .try_into()
        .unwrap()
});

static C: Lazy<[[Fr; 3]; 65]> = Lazy::new(|| {
    constants::C
        .iter()
        .map(|row| {
            row.iter()
                .map(Fr::try_from)
                .collect::<Result<Vec<Fr>, _>>()
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect::<Vec<[Fr; 3]>>()
        .try_into()
        .unwrap()
});

/// Compute the one-value Poseidon hash function.
///
/// # Panics
///
/// Panics if `input` is not a valid field element.
#[must_use]
pub fn hash1(value: U256) -> U256 {
    let value = value.try_into().unwrap();
    let mut state = [Fr::zero(), value];

    for i in 0..64 {
        // Add round constants
        state[0] += C1[i][0];
        state[1] += C1[i][1];

        // SubWords, S-Box: Exponentiate
        state[0] = state[0].pow([5]);
        if !(4..60).contains(&i) {
            state[1] = state[1].pow([5]);
        }

        // MixLayer: Multiply by maximum distance separable matrix
        state = [
            M1[0][0] * state[0] + M1[0][1] * state[1],
            M1[1][0] * state[0] + M1[1][1] * state[1],
        ];
    }
    state[0].into()
}

/// Compute the two-value Poseidon hash function.
///
/// # Panics
///
/// Panics if `left`, `right` are not a valid field element.
#[must_use]
pub fn hash2(left: U256, right: U256) -> U256 {
    let left = left.try_into().unwrap();
    let right = right.try_into().unwrap();
    let mut state = [Fr::zero(), left, right];

    for i in 0..65 {
        // Add round constants
        state[0] += C[i][0];
        state[1] += C[i][1];
        state[2] += C[i][2];

        // SubWords, S-Box: Exponentiate
        state[0] = state[0].pow([5]);
        if !(4..61).contains(&i) {
            state[1] = state[1].pow([5]);
            state[2] = state[2].pow([5]);
        }

        // MixLayer: Multiply by maximum distance separable matrix
        state = [
            M[0][0] * state[0] + M[0][1] * state[1] + M[0][2] * state[2],
            M[1][0] * state[0] + M[1][1] * state[1] + M[1][2] * state[2],
            M[2][0] * state[0] + M[2][1] * state[1] + M[2][2] * state[2],
        ];
    }
    state[0].into()
}

#[cfg(test)]
mod tests {
    use ruint::uint;

    use super::*;

    #[test]
    fn test_hash1() {
        uint! {
            assert_eq!(hash1(0_U256), 0x2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c_U256);

        }
    }

    #[test]
    fn test_hash2() {
        uint! {
            assert_eq!(hash2(0_U256, 0_U256), 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864_U256);
            assert_eq!(hash2(31213_U256, 132_U256), 0x303f59cd0831b5633bcda50514521b33776b5d4280eb5868ba1dbbe2e4d76ab5_U256);
        }
    }
}
