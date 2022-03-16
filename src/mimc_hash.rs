//! Hash function compatible with Semaphore's Merkle tree hash function
//!
//! See <https://github.com/appliedzkp/semaphore/blob/master/circuits/circom/semaphore-base.circom#L10>
//! See <https://github.com/kobigurk/circomlib/blob/4284dc1ef984a204db08864f5da530c97f9376ef/circuits/mimcsponge.circom>
//! See <https://github.com/iden3/circomlibjs/blob/main/src/mimcsponge.js>
//!
//! # To do
//!
//! * Instantiate a `PrimeField` to use Montgomery form.

use once_cell::sync::Lazy;
use tiny_keccak::{Hasher as _, Keccak};
use zkp_u256::U256;

const NUM_ROUNDS: usize = 220;

static MODULUS: Lazy<U256> = Lazy::new(|| {
    U256::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap()
});

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

static ROUND_CONSTANTS: Lazy<[U256; NUM_ROUNDS]> = Lazy::new(|| {
    const SEED: &str = "mimcsponge";
    let mut result = [U256::ZERO; NUM_ROUNDS];
    let mut bytes = keccak256(SEED.as_bytes());
    for constant in result[1..NUM_ROUNDS - 1].iter_mut() {
        bytes = keccak256(&bytes);
        *constant = U256::from_bytes_be(&bytes);
        *constant %= &*MODULUS;
    }
    result
});

/// See <https://github.com/iden3/circomlibjs/blob/main/src/mimcsponge.js#L44>
fn mix(left: &mut U256, right: &mut U256) {
    debug_assert!(*left < *MODULUS);
    debug_assert!(*right < *MODULUS);
    for round_constant in &*ROUND_CONSTANTS {
        // Modulus is less than 2**252, so addition doesn't overflow
        let t = (&*left + round_constant) % &*MODULUS;
        let t2 = t.mulmod(&t, &*MODULUS);
        let t4 = t2.mulmod(&t2, &*MODULUS);
        let t5 = t.mulmod(&t4, &*MODULUS);
        *right += t5;
        *right %= &*MODULUS;
        std::mem::swap(left, right);
    }
    std::mem::swap(left, right);
}

#[must_use]
pub fn hash(values: &[U256]) -> U256 {
    let mut left = U256::ZERO;
    let mut right = U256::ZERO;
    for value in values {
        let value = value % &*MODULUS;
        left += value;
        left %= &*MODULUS;
        mix(&mut left, &mut right);
    }
    left
}

#[cfg(test)]
pub mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_round_constants() {
        // See <https://github.com/kobigurk/circomlib/blob/4284dc1ef984a204db08864f5da530c97f9376ef/circuits/mimcsponge.circom#L44>
        assert_eq!(ROUND_CONSTANTS[0], U256::ZERO);
        assert_eq!(
            ROUND_CONSTANTS[1],
            U256::from_decimal_str(
                "7120861356467848435263064379192047478074060781135320967663101236819528304084"
            )
            .unwrap()
        );
        assert_eq!(
            ROUND_CONSTANTS[2],
            U256::from_decimal_str(
                "5024705281721889198577876690145313457398658950011302225525409148828000436681"
            )
            .unwrap()
        );
        assert_eq!(
            ROUND_CONSTANTS[218],
            U256::from_decimal_str(
                "2119542016932434047340813757208803962484943912710204325088879681995922344971"
            )
            .unwrap()
        );
        assert_eq!(ROUND_CONSTANTS[219], U256::ZERO);
    }

    #[test]
    fn test_mix() {
        let mut left = U256::ONE;
        let mut right = U256::ZERO;
        mix(&mut left, &mut right);
        assert_eq!(
            left,
            U256::from_decimal_str(
                "8792246410719720074073794355580855662772292438409936688983564419486782556587"
            )
            .unwrap()
        );
        assert_eq!(
            right,
            U256::from_decimal_str(
                "7326554092124867281481480523863654579712861994895051796475958890524736238844"
            )
            .unwrap()
        );
        left += U256::from(2);
        mix(&mut left, &mut right);
        assert_eq!(
            left,
            U256::from_decimal_str(
                "19814528709687996974327303300007262407299502847885145507292406548098437687919"
            )
            .unwrap()
        );
        assert_eq!(
            right,
            U256::from_decimal_str(
                "3888906192024793285683241274210746486868893421288515595586335488978789653213"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_hash() {
        // See <https://github.com/iden3/circomlibjs/blob/3f84f4fbf77bebdf1722d851c1ad9b62cbf3d120/test/mimcsponge.js#L6>
        assert_eq!(
            hash(&[U256::from(1_u64), U256::from(2_u64)]),
            U256::from_bytes_be(&hex!(
                "2bcea035a1251603f1ceaf73cd4ae89427c47075bb8e3a944039ff1e3d6d2a6f"
            ))
        );
        assert_eq!(
            hash(&[
                U256::from(1_u64),
                U256::from(2_u64),
                U256::from(3_u64),
                U256::from(4_u64)
            ]),
            U256::from_bytes_be(&hex!(
                "03e86bdc4eac70bd601473c53d8233b145fe8fd8bf6ef25f0b217a1da305665c"
            ))
        );
    }
}

#[cfg(feature = "bench")]
pub mod bench {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        bench_mix(criterion);
    }

    fn bench_mix(criterion: &mut Criterion) {
        let mut left = U256::ONE;
        let mut right = U256::ZERO;
        criterion.bench_function("mimc_mix", move |bencher| {
            bencher.iter(|| mix(&mut left, &mut right));
        });
    }
}
