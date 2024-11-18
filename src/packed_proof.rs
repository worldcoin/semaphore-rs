use std::{
    fmt::Display,
    str::{from_utf8, FromStr},
};

use crate::protocol::Proof;
use ethabi::{decode, encode, ethereum_types::U256, ParamType, Token};
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
        let b = (
            [decoded_uint_array[2], decoded_uint_array[3]],
            [decoded_uint_array[4], decoded_uint_array[5]],
        );
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
            (
                [U256::from(3), U256::from(4)],
                [U256::from(5), U256::from(6)],
            ),
            (U256::from(7), U256::from(8)),
        );

        let packed_proof = PackedProof::from(proof);

        assert_eq!(packed_proof.to_string(), "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008");

        let proof2 = Proof::from(packed_proof);

        assert_eq!(proof, proof2);
    }

    #[test]
    fn test_parse_from_string() {
        let packed_proof_str =  "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008";

        let packed_proof = PackedProof::from_str(packed_proof_str).unwrap();

        let expected_proof = Proof(
            (U256::from(1), U256::from(2)),
            (
                [U256::from(3), U256::from(4)],
                [U256::from(5), U256::from(6)],
            ),
            (U256::from(7), U256::from(8)),
        );

        let proof: Proof = packed_proof.into();

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_parse_from_string_without_prefix() {
        // note the lack of 0x prefix
        let packed_proof_str =  "00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008";

        let packed_proof = PackedProof::from_str(packed_proof_str).unwrap();

        let expected_proof = Proof(
            (U256::from(5), U256::from(6)),
            (
                [U256::from(3), U256::from(4)],
                [U256::from(5), U256::from(6)],
            ),
            (U256::from(7), U256::from(8)),
        );

        let proof: Proof = packed_proof.into();

        assert_eq!(proof, expected_proof);
    }

    #[test]
    fn test_serialize_proof_to_json() {
        let packed_proof_str =  "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008";

        let packed_proof = PackedProof::from_str(packed_proof_str).unwrap();
        let proof: Proof = packed_proof.into();

        let serialized = serde_json::to_value(proof).unwrap();

        assert_eq!(
            serialized,
            serde_json::json!([
                ["0x1", "0x2"],
                [["0x3", "0x4"], ["0x5", "0x6"]],
                ["0x7", "0x8"]
            ])
        );
    }

    #[test]
    fn test_serialize_proof_to_json_real_numbers() {
        let packed_proof_str =  "0x15c1fc6907219676890dfe147ee6f10b580c7881dddacb1567b3bcbfc513a54d233afda3efff43a7631990d2e79470abcbae3ccad4b920476e64745bfe97bb0a0c8c7d7434c382d590d601d951c29c8463d555867db70f9e84f7741c81c2e1e6241d2ddf1c9e6670a24109a0e9c915cd6e07d0248a384dd38d3c91e9b0419f5f0b23c5467a06eff56cc2c246ada1e7d5705afc4dc8b43fd5a6972c679a2019c5091ed6522f7924d3674d08966a008f947f9aa016a4100bb12f911326f3e1befd0acdf5a5996e00933206cbec48f3bbdcee2a4ca75f8db911c00001e5a05474872446d6f1c1506837392a30fdc73d66fd89f4e1b1a5d14b93e2ad0c5f7b777520";

        let packed_proof = PackedProof::from_str(packed_proof_str).unwrap();
        let proof: Proof = packed_proof.into();

        let serialized = serde_json::to_value(proof).unwrap();

        assert_eq!(
            serialized,
            serde_json::json!([
                [
                    "0x15c1fc6907219676890dfe147ee6f10b580c7881dddacb1567b3bcbfc513a54d",
                    "0x233afda3efff43a7631990d2e79470abcbae3ccad4b920476e64745bfe97bb0a"
                ],
                [
                    [
                        "0xc8c7d7434c382d590d601d951c29c8463d555867db70f9e84f7741c81c2e1e6",
                        "0x241d2ddf1c9e6670a24109a0e9c915cd6e07d0248a384dd38d3c91e9b0419f5f"
                    ],
                    [
                        "0xb23c5467a06eff56cc2c246ada1e7d5705afc4dc8b43fd5a6972c679a2019c5",
                        "0x91ed6522f7924d3674d08966a008f947f9aa016a4100bb12f911326f3e1befd"
                    ]
                ],
                [
                    "0xacdf5a5996e00933206cbec48f3bbdcee2a4ca75f8db911c00001e5a0547487",
                    "0x2446d6f1c1506837392a30fdc73d66fd89f4e1b1a5d14b93e2ad0c5f7b777520"
                ]
            ])
        );
    }

    #[test]
    fn test_deserialize_proof_from_json() {
        let proof_str = "[
            [
                \"0x15c1fc6907219676890dfe147ee6f10b580c7881dddacb1567b3bcbfc513a54d\",
                \"0x233afda3efff43a7631990d2e79470abcbae3ccad4b920476e64745bfe97bb0a\"
            ],
            [
                [
                    \"0xc8c7d7434c382d590d601d951c29c8463d555867db70f9e84f7741c81c2e1e6\",
                    \"0x241d2ddf1c9e6670a24109a0e9c915cd6e07d0248a384dd38d3c91e9b0419f5f\"
                ],
                [
                    \"0xb23c5467a06eff56cc2c246ada1e7d5705afc4dc8b43fd5a6972c679a2019c5\",
                    \"0x91ed6522f7924d3674d08966a008f947f9aa016a4100bb12f911326f3e1befd\"
                ]
            ],
            [
                \"0xacdf5a5996e00933206cbec48f3bbdcee2a4ca75f8db911c00001e5a0547487\",
                \"0x2446d6f1c1506837392a30fdc73d66fd89f4e1b1a5d14b93e2ad0c5f7b777520\"
            ]
        ]";

        let proof = serde_json::from_str::<Proof>(proof_str).unwrap();

        let packed_proof = PackedProof::from(proof);

        let expected_proof =  "0x15c1fc6907219676890dfe147ee6f10b580c7881dddacb1567b3bcbfc513a54d233afda3efff43a7631990d2e79470abcbae3ccad4b920476e64745bfe97bb0a0c8c7d7434c382d590d601d951c29c8463d555867db70f9e84f7741c81c2e1e6241d2ddf1c9e6670a24109a0e9c915cd6e07d0248a384dd38d3c91e9b0419f5f0b23c5467a06eff56cc2c246ada1e7d5705afc4dc8b43fd5a6972c679a2019c5091ed6522f7924d3674d08966a008f947f9aa016a4100bb12f911326f3e1befd0acdf5a5996e00933206cbec48f3bbdcee2a4ca75f8db911c00001e5a05474872446d6f1c1506837392a30fdc73d66fd89f4e1b1a5d14b93e2ad0c5f7b777520";

        assert_eq!(packed_proof.to_string(), expected_proof);
    }

    #[test]
    fn test_invalid_parsing() {
        // note this is only 7 numbers
        let packed_proof_str =  "0x0000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000007";
        PackedProof::from_str(packed_proof_str).expect_err("parsing should fail");

        // not a valid number
        let packed_proof_str =  "0000000000000000p000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000005000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000000000000000000000008";
        PackedProof::from_str(packed_proof_str).expect_err("parsing should fail");

        // completely invalid
        let packed_proof_str = "0x0";
        PackedProof::from_str(packed_proof_str).expect_err("parsing should fail");
    }
}
