use crate::util::keccak256;
use ruint::{aliases::U256, uint};

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
#[allow(clippy::missing_panics_doc)]
pub fn hash_to_field(data: &[u8]) -> Field {
    // Never panics because the target uint is large enough.
    let n = U256::try_from_be_slice(&keccak256(data)).unwrap();
    // Shift right one byte to make it fit in the field
    n >> 8
}
