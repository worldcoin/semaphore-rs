use crate::{
    hash::Hash,
    merkle_tree::{self, Hasher, MerkleTree},
};
use ff::{PrimeField, PrimeFieldRepr};
use once_cell::sync::Lazy;
use poseidon_rs::{Fr, FrRepr, Poseidon};
use serde::Serialize;

static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

#[allow(dead_code)]
pub type PoseidonTree = MerkleTree<PoseidonHash>;
#[allow(dead_code)]
pub type Branch = merkle_tree::Branch<PoseidonHash>;
#[allow(dead_code)]
pub type Proof = merkle_tree::Proof<PoseidonHash>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PoseidonHash;

#[allow(clippy::fallible_impl_from)] // TODO
impl From<&Hash> for Fr {
    fn from(hash: &Hash) -> Self {
        let mut repr = FrRepr::default();
        repr.read_be(&hash.as_bytes_be()[..]).unwrap();
        Self::from_repr(repr).unwrap()
    }
}

#[allow(clippy::fallible_impl_from)] // TODO
impl From<Fr> for Hash {
    fn from(fr: Fr) -> Self {
        let mut bytes = [0_u8; 32];
        fr.into_repr().write_be(&mut bytes[..]).unwrap();
        Self::from_bytes_be(bytes)
    }
}

impl Hasher for PoseidonHash {
    type Hash = Hash;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        POSEIDON
            .hash(vec![left.into(), right.into()])
            .unwrap() // TODO
            .into()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_tree_4() {
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        let tree = PoseidonTree::new(3, LEAF);
        assert_eq!(tree.num_leaves(), 4);
        assert_eq!(
            tree.root(),
            Hash::from_bytes_be(hex!(
                "1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1"
            ))
        );
        let proof = tree.proof(3).expect("proof should exist");
        assert_eq!(
            proof,
            crate::merkle_tree::Proof(vec![
                Branch::Right(LEAF),
                Branch::Right(Hash::from_bytes_be(hex!(
                    "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"
                ))),
            ])
        );
    }
}
