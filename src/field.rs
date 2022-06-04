use crate::util::{bytes_from_hex, bytes_to_hex, deserialize_bytes, keccak256, serialize_bytes};
use ark_bn254::Fr as ArkField;
use ark_ff::{BigInteger as _, PrimeField as _};
use core::{
    fmt::{Debug, Display},
    str,
    str::FromStr,
};
use ff::{PrimeField as _, PrimeFieldRepr as _};
use num_bigint::{BigInt, Sign};
use poseidon_rs::Fr as PosField;
use ruint::{aliases::U256, uint};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An element of the BN254 scalar field Fr.
///
/// Represented as a big-endian byte vector without Montgomery reduction.
// TODO: Make sure value is always reduced.
pub type Field = U256;

// See <https://docs.rs/ark-bn254/latest/ark_bn254>
pub const MODULUS: Field =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

/// Hash arbitrary data to a field element.
///
/// This is used to create `signal_hash` and `external_nullifier_hash`.
#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn hash_to_field(data: &[u8]) -> Field {
    let n = U256::try_from_be_slice(&keccak256(data)).unwrap();
    // Shift right one byte to make it fit in the field
    n >> 8
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::Field as _;

    #[test]
    fn test_modulus_identical() {
        assert_eq!(PosField::char().0, ArkField::characteristic());
    }

    #[test]
    fn test_field_serde() {
        let value = Field::from(0x1234_5678);
        let serialized = serde_json::to_value(value).unwrap();
        let deserialized = serde_json::from_value(serialized).unwrap();
        assert_eq!(value, deserialized);
    }

    // #[test]
    // fn test_ark_pos_ark_roundtrip() {
    //     let mut rng = ChaChaRng::seed_from_u64(123);
    //     for _ in 0..1000 {
    //         let n = Field::rand(&mut rng);
    //         let m = poseidon_to_ark(ark_to_poseidon(n));
    //         assert_eq!(n, m);
    //     }
    // }
}
