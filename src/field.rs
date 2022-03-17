use crate::util::{keccak256, trim_hex_prefix};
use ark_bn254::Fr as ArkField;
use ark_ff::{BigInteger as _, PrimeField as _};
use core::{
    fmt::{Formatter, Result as FmtResult},
    str,
    str::FromStr,
};
use ff::{PrimeField as _, PrimeFieldRepr as _};
use hex::encode_to_slice;
use num_bigint::{BigInt, Sign};
use poseidon_rs::Fr as PosField;
use serde::{
    de::{Error as DeError, Visitor},
    Deserialize, Serialize, Serializer,
};

/// An element of the BN254 scalar field Fr.
///
/// Represented as a big-endian byte vector without Montgomery reduction.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
// TODO: Make sure value is always reduced.
pub struct Field([u8; 32]);

impl Field {
    /// Construct a field element from a big-endian byte vector.
    #[must_use]
    pub fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        ArkField::from_be_bytes_mod_order(bytes).into()
    }
}

impl From<u64> for Field {
    fn from(value: u64) -> Self {
        ArkField::from(value).into()
    }
}

impl From<ArkField> for Field {
    fn from(value: ArkField) -> Self {
        let mut bytes = [0_u8; 32];
        let byte_vec = value.into_repr().to_bytes_be();
        bytes.copy_from_slice(&byte_vec[..]);
        Self(bytes)
    }
}

impl From<Field> for ArkField {
    fn from(value: Field) -> Self {
        Self::from_be_bytes_mod_order(&value.0[..])
    }
}

impl From<PosField> for Field {
    fn from(value: PosField) -> Self {
        let mut bytes = [0u8; 32];
        value
            .into_repr()
            .write_be(&mut bytes[..])
            .expect("write to correctly sized slice always succeeds");
        Self(bytes)
    }
}

impl From<Field> for PosField {
    fn from(value: Field) -> Self {
        let mut repr = <Self as ff::PrimeField>::Repr::default();
        repr.read_be(&value.0[..])
            .expect("read from correctly sized slice always succeeds");
        Self::from_repr(repr).expect("value is always in range")
    }
}

impl From<Field> for BigInt {
    fn from(value: Field) -> Self {
        Self::from_bytes_be(Sign::Plus, &value.0[..])
    }
}

impl Serialize for Field {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            // Write as a 0x prefixed lower-case hex string
            let mut buffer = [0u8; 66];
            buffer[0] = b'0';
            buffer[1] = b'x';
            encode_to_slice(&self.0, &mut buffer[2..]).expect("the buffer is correctly sized");
            let string = str::from_utf8(&buffer).expect("the buffer is valid UTF-8");
            serializer.serialize_str(string)
        } else {
            // Write as bytes directly
            serializer.serialize_bytes(&self.0)
        }
    }
}

/// Parse Hash from hex string.
/// Hex strings can be upper/lower/mixed case and have an optional `0x` prefix
/// but they must always be exactly 32 bytes.
impl FromStr for Field {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let str = trim_hex_prefix(s);
        let mut out = [0_u8; 32];
        hex::decode_to_slice(str, &mut out)?;

        // TODO: Reduce
        Ok(Self(out))
    }
}

/// Deserialize human readable hex strings or byte arrays into hashes.
/// Hex strings can be upper/lower/mixed case and have an optional `0x` prefix
/// but they must always be exactly 32 bytes.
impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(StrVisitor)
        } else {
            // TODO: Reduce
            <[u8; 32]>::deserialize(deserializer).map(Field)
        }
    }
}

struct StrVisitor;

impl<'de> Visitor<'de> for StrVisitor {
    type Value = Field;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("a 32 byte hex string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Field::from_str(value).map_err(|e| E::custom(format!("Error in hex: {}", e)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Field::from_str(value).map_err(|e| E::custom(format!("Error in hex: {}", e)))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Field::from_str(&value).map_err(|e| E::custom(format!("Error in hex: {}", e)))
    }
}

/// Hash arbitrary data to a field element.
///
/// This is used to create `signal_hash` and `external_nullifier_hash`.
#[must_use]
#[allow(clippy::module_name_repetitions)]
pub fn hash_to_field(data: &[u8]) -> Field {
    let hash = keccak256(data);
    // Shift right one byte to make it fit in the field
    let mut bytes = [0_u8; 32];
    bytes[1..].copy_from_slice(&hash[..31]);
    Field(bytes)
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
