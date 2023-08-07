use core::{
    fmt::{Formatter, Result as FmtResult},
    str,
};
use serde::{
    de::{Error as DeError, Visitor},
    Deserializer, Serializer,
};
use tiny_keccak::{Hasher as _, Keccak};

pub(crate) fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

pub(crate) fn bytes_to_hex<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u8; M] {
    // TODO: Replace `M` with a const expression once it's stable.
    debug_assert_eq!(M, 2 * N + 2);
    let mut result = [0u8; M];
    result[0] = b'0';
    result[1] = b'x';
    hex::encode_to_slice(&bytes[..], &mut result[2..]).expect("the buffer is correctly sized");
    result
}

/// Helper to serialize byte arrays
pub(crate) fn serialize_bytes<const N: usize, const M: usize, S: Serializer>(
    serializer: S,
    bytes: &[u8; N],
) -> Result<S::Ok, S::Error> {
    // TODO: Replace `M` with a const expression once it's stable.
    debug_assert_eq!(M, 2 * N + 2);
    if serializer.is_human_readable() {
        // Write as a 0x prefixed lower-case hex string
        let buffer = bytes_to_hex::<N, M>(bytes);
        let string = str::from_utf8(&buffer).expect("the buffer is valid UTF-8");
        serializer.serialize_str(string)
    } else {
        // Write as bytes directly
        serializer.serialize_bytes(&bytes[..])
    }
}

/// Helper to deserialize byte arrays from hex strings
///
/// TODO: How does it handle strings that are to short?
pub(crate) fn bytes_from_hex<const N: usize>(s: &str) -> Result<[u8; N], hex::FromHexError> {
    let str = trim_hex_prefix(s);
    let mut result = [0_u8; N];
    hex::decode_to_slice(str, &mut result)?;
    Ok(result)
}

/// Helper function to remove  optionally `0x` prefix from hex strings.
fn trim_hex_prefix(str: &str) -> &str {
    if str.len() >= 2 && (&str[..2] == "0x" || &str[..2] == "0X") {
        &str[2..]
    } else {
        str
    }
}

/// Helper to deserialize byte arrays.
pub(crate) fn deserialize_bytes<'de, const N: usize, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    if deserializer.is_human_readable() {
        struct StrVisitor<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for StrVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "a {N} byte hex string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                bytes_from_hex(value).map_err(|e| E::custom(format!("Error in hex: {e}")))
            }
        }
        deserializer.deserialize_str(StrVisitor)
    } else {
        struct ByteVisitor<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for ByteVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, formatter: &mut Formatter) -> FmtResult {
                write!(formatter, "{N} bytes of binary data")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                if value.len() != N {
                    return Err(E::invalid_length(value.len(), &self));
                }
                let mut result = [0_u8; N];
                result.copy_from_slice(value);
                Ok(result)
            }
        }
        deserializer.deserialize_bytes(ByteVisitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serialize_bytes_hex() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut ser = serde_json::Serializer::new(Vec::new());
        serialize_bytes::<16, 34, _>(&mut ser, &bytes).unwrap();
        let json = ser.into_inner();
        assert_eq!(json, b"\"0x0102030405060708090a0b0c0d0e0f10\"");
    }

    #[test]
    fn test_serialize_bytes_bin() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut bin: Vec<u8> = Vec::new();
        {
            let mut ser = bincode::Serializer::new(&mut bin, bincode::options());
            serialize_bytes::<16, 34, _>(&mut ser, &bytes).unwrap();
        }
        // Bincode appears to prefix with a length.
        assert_eq!(bin, [
            16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        ]);
    }
}
