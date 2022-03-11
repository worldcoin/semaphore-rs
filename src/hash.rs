use ethers_core::types::U256;
use num_bigint::{BigInt, Sign};
use serde::{
    de::{Error as DeError, Visitor},
    ser::Error as _,
    Deserialize, Serialize,
};
use std::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    str::{from_utf8, FromStr},
};

/// Container for 256-bit hash values.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    #[must_use]
    pub const fn from_bytes_be(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes_be(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Debug print hashes using `hex!(..)` literals.
impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Hash(hex!(\"{}\"))", hex::encode(&self.0))
    }
}

/// Display print hashes as `0x...`.
impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

/// Conversion from Ether U256
impl From<&Hash> for U256 {
    fn from(hash: &Hash) -> Self {
        Self::from_big_endian(hash.as_bytes_be())
    }
}

/// Conversion to Ether U256
impl From<U256> for Hash {
    fn from(u256: U256) -> Self {
        let mut bytes = [0_u8; 32];
        u256.to_big_endian(&mut bytes);
        Self::from_bytes_be(bytes)
    }
}

/// Conversion from vec
impl From<Vec<u8>> for Hash {
    fn from(vec: Vec<u8>) -> Self {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&vec[0..32]);
        Self::from_bytes_be(bytes)
    }
}

/// Conversion to `BigInt`
impl From<Hash> for BigInt {
    fn from(hash: Hash) -> Self {
        Self::from_bytes_be(Sign::Plus, hash.as_bytes_be())
    }
}

impl From<&Hash> for BigInt {
    fn from(hash: &Hash) -> Self {
        Self::from_bytes_be(Sign::Plus, hash.as_bytes_be())
    }
}

/// Parse Hash from hex string.
/// Hex strings can be upper/lower/mixed case and have an optional `0x` prefix
/// but they must always be exactly 32 bytes.
impl FromStr for Hash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let str = trim_hex_prefix(s);
        let mut out = [0_u8; 32];
        hex::decode_to_slice(str, &mut out)?;
        Ok(Self(out))
    }
}

/// Serialize hashes into human readable hex strings or byte arrays.
/// Hex strings are lower case without prefix and always 32 bytes.
impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut hex_ascii = [0_u8; 64];
            hex::encode_to_slice(self.0, &mut hex_ascii)
                .map_err(|e| S::Error::custom(format!("Error hex encoding: {}", e)))?;
            from_utf8(&hex_ascii)
                .map_err(|e| S::Error::custom(format!("Invalid hex encoding: {}", e)))?
                .serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

/// Deserialize human readable hex strings or byte arrays into hashes.
/// Hex strings can be upper/lower/mixed case and have an optional `0x` prefix
/// but they must always be exactly 32 bytes.
impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(HashStrVisitor)
        } else {
            <[u8; 32]>::deserialize(deserializer).map(Hash)
        }
    }
}

struct HashStrVisitor;

impl<'de> Visitor<'de> for HashStrVisitor {
    type Value = Hash;

    fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
        formatter.write_str("a 32 byte hex string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Hash::from_str(value).map_err(|e| E::custom(format!("Error in hex: {}", e)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Hash::from_str(value).map_err(|e| E::custom(format!("Error in hex: {}", e)))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Hash::from_str(&value).map_err(|e| E::custom(format!("Error in hex: {}", e)))
    }
}

/// Helper function to optionally remove `0x` prefix from hex strings.
fn trim_hex_prefix(str: &str) -> &str {
    if str.len() >= 2 && (&str[..2] == "0x" || &str[..2] == "0X") {
        &str[2..]
    } else {
        str
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use hex_literal::hex;
    use serde_json::{from_str, to_string};

    #[test]
    fn test_serialize() {
        let hash = Hash([0; 32]);
        assert_eq!(
            to_string(&hash).unwrap(),
            "\"0000000000000000000000000000000000000000000000000000000000000000\""
        );
        let hash = Hash(hex!(
            "1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe"
        ));
        assert_eq!(
            to_string(&hash).unwrap(),
            "\"1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe\""
        );
    }

    #[test]
    fn test_deserialize() {
        assert_eq!(
            from_str::<Hash>(
                "\"0x1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe\""
            )
            .unwrap(),
            Hash(hex!(
                "1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe"
            ))
        );
        assert_eq!(
            from_str::<Hash>(
                "\"0X1C4823575d154474EE3e5ac838d002456a815181437afd14f126da58a9912bbe\""
            )
            .unwrap(),
            Hash(hex!(
                "1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe"
            ))
        );
    }
}
