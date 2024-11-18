use crate::util::{bytes_from_hex, bytes_to_hex, deserialize_bytes, serialize_bytes};
use core::{
    fmt::{Debug, Display},
    str,
    str::FromStr,
};
use ethabi::ethereum_types::U256;
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

impl Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = bytes_to_hex::<32, 66>(&self.0);
        let hex_str = str::from_utf8(&hex).expect("hex is always valid utf8");
        write!(f, "Field({hex_str})")
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = bytes_to_hex::<32, 66>(&self.0);
        let hex_str = str::from_utf8(&hex).expect("hex is always valid utf8");
        write!(f, "{hex_str}")
    }
}

/// Parse Hash from hex string.
/// Hex strings can be upper/lower/mixed case and have an optional `0x` prefix
/// but they must always be exactly 32 bytes.
impl FromStr for Hash {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bytes_from_hex::<32>(s).map(Self)
    }
}

/// Serialize hashes into human readable hex strings or byte arrays.
/// Hex strings are lower case without prefix and always 32 bytes.
impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes::<32, 66, S>(serializer, &self.0)
    }
}

/// Deserialize human readable hex strings or byte arrays into hashes.
/// Hex strings can be upper/lower/mixed case and have an optional `0x` prefix
/// but they must always be exactly 32 bytes.
impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes::<32, _>(deserializer)?;
        Ok(Self(bytes))
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
            "\"0x0000000000000000000000000000000000000000000000000000000000000000\""
        );
        let hash = Hash(hex!(
            "1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe"
        ));
        assert_eq!(
            to_string(&hash).unwrap(),
            "\"0x1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe\""
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
