use std::{
    fmt::Display,
    str::{from_utf8, FromStr},
};

use crate::protocol::Proof;
use ethabi::{decode, encode, ParamType, Token};
use ethers_core::types::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::util::{bytes_from_hex, bytes_to_hex, deserialize_bytes, serialize_bytes};

/// A packed proof is a representation of the ZKP in a single attribute (as
/// opposed to array of arrays) which is easier to transport
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedProof(pub [u8; 256]);

impl From<Proof> for PackedProof {
    fn from(proof: Proof) -> Self {
        let tokens = Token::FixedArray(vec![
            Token::Uint(proof.0 .0),
            Token::Uint(proof.0 .1),
            Token::Uint(proof.1 .0[0]),
            Token::Uint(proof.1 .0[1]),
            Token::Uint(proof.1 .1[0]),
            Token::Uint(proof.1 .1[1]),
            Token::Uint(proof.2 .0),
            Token::Uint(proof.2 .1),
        ]);

        let bytes = encode(&[tokens]);
        let mut encoded = [0u8; 256];
        encoded.copy_from_slice(&bytes[..256]);
        Self(encoded)
    }
}

impl From<PackedProof> for Proof {
    fn from(proof: PackedProof) -> Self {
        let decoded = decode(&vec![ParamType::Uint(256); 8], &proof.0).unwrap();
        let decoded_uint_array = decoded
            .into_iter()
            .map(|x| x.into_uint().unwrap())
            .collect::<Vec<U256>>();

        let a = (decoded_uint_array[0], decoded_uint_array[1]);
        let b = ([decoded_uint_array[2], decoded_uint_array[3]], [
            decoded_uint_array[4],
            decoded_uint_array[5],
        ]);
        let c = (decoded_uint_array[6], decoded_uint_array[7]);
        Self(a, b, c)
    }
}

impl Display for PackedProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = bytes_to_hex::<256, 514>(&self.0);
        write!(
            f,
            "{}",
            from_utf8(&hex).expect("failed to convert to string")
        )
    }
}

impl FromStr for PackedProof {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bytes_from_hex::<256>(s).map(Self)
    }
}

impl Serialize for PackedProof {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_bytes::<256, 514, S>(serializer, &self.0)
    }
}

impl<'de> Deserialize<'de> for PackedProof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = deserialize_bytes::<256, _>(deserializer)?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_serializing_proof_into_packed_proof() {
        let proof = Proof(
            (U256::from(1), U256::from(2)),
            ([U256::from(3), U256::from(4)], [
                U256::from(5),
                U256::from(6),
            ]),
            (U256::from(7), U256::from(8)),
        );

        let packed_proof = PackedProof::from(proof);

        assert_eq!(packed_proof.to_string(), "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008");

        dbg!(packed_proof.to_string());

        let proof2 = Proof::from(packed_proof);

        assert_eq!(proof, proof2);
    }
}
