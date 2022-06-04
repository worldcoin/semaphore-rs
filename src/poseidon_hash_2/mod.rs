mod constants;

use ark_bn254::Fr;
use ark_ff::{Field, Zero};
use once_cell::sync::Lazy;
use ruint::aliases::U256;

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

pub fn hash(left: U256, right: U256) -> U256 {
    let left = left.try_into().unwrap();
    let right = right.try_into().unwrap();
    let mut state = [Fr::zero(), left, right];
    for i in 0..65 {
        // Add round constants
        state[0] += C[i][0];
        state[1] += C[i][1];
        state[2] += C[i][2];

        // Exponentiate
        state[0] = state[0].pow(&[5]);
        if !(4..=61).contains(&i) {
            state[1] = state[1].pow(&[5]);
            state[2] = state[2].pow(&[5]);
        }

        // Multiply by mixing matrix
        state = [
            M[0][1] * state[0] + M[0][1] * state[1] + M[0][2] * state[2],
            M[1][1] * state[0] + M[1][1] * state[1] + M[1][2] * state[2],
            M[2][1] * state[0] + M[2][1] * state[1] + M[2][2] * state[2],
        ];
    }
    state[0].into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::uint;

    #[test]
    fn test_posseidon() {
        uint! {
            assert_eq!(hash(0_U256.into(), 0_U256.into()), 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864_U256);
        }
    }
}
