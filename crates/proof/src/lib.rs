use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

#[cfg(feature = "ark")]
mod ark;

pub mod compression;
pub mod packing;

// Matches the private G1Tup type in ark-circom.
pub type G1 = (U256, U256);

// Matches the private G2Tup type in ark-circom.
pub type G2 = ([U256; 2], [U256; 2]);

/// Wrap a proof object so we have serde support
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof(pub G1, pub G2, pub G1);

impl Proof {
    pub const fn from_flat(flat: [U256; 8]) -> Self {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = flat;
        Self((x0, x1), ([x2, x3], [x4, x5]), (x6, x7))
    }

    pub const fn flatten(self) -> [U256; 8] {
        let Self((a0, a1), ([bx0, bx1], [by0, by1]), (c0, c1)) = self;
        [a0, a1, bx0, bx1, by0, by1, c0, c1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deser() {
        let s = r#"[["0x1","0x2"],[["0x3","0x4"],["0x5","0x6"]],["0x7","0x8"]]"#;

        let deserialized: Proof = serde_json::from_str(s).unwrap();
        let reserialized = serde_json::to_string(&deserialized).unwrap();

        assert_eq!(s, reserialized);
    }
}
