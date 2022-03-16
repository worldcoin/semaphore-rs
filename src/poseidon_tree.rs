use crate::{
    hash::Hash,
    merkle_tree::{self, Hasher, MerkleTree},
    posseidon_hash, Field,
};
use ark_ff::{PrimeField, ToBytes};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub type PoseidonTree = MerkleTree<PoseidonHash>;
#[allow(dead_code)]
pub type Branch = merkle_tree::Branch<PoseidonHash>;
#[allow(dead_code)]
pub type Proof = merkle_tree::Proof<PoseidonHash>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHash;

#[allow(clippy::fallible_impl_from)] // TODO
impl From<&Hash> for Field {
    fn from(hash: &Hash) -> Self {
        Field::from_be_bytes_mod_order(&hash.0)
    }
}

#[allow(clippy::fallible_impl_from)] // TODO
impl From<Hash> for Field {
    fn from(hash: Hash) -> Self {
        Field::from_be_bytes_mod_order(&hash.0)
    }
}

#[allow(clippy::fallible_impl_from)] // TODO
impl From<Field> for Hash {
    fn from(n: Field) -> Self {
        let mut bytes = [0_u8; 32];
        n.into_repr()
            .write(&mut bytes[..])
            .expect("write should succeed");
        bytes.reverse(); // Convert to big endian
        Self(bytes)
    }
}

impl Hasher for PoseidonHash {
    type Hash = Hash;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        posseidon_hash(&[left.into(), right.into()]).into()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_ff::UniformRand;
    use hex_literal::hex;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_ark_hash_ark_roundtrip() {
        use ark_ff::One;
        let mut rng = ChaChaRng::seed_from_u64(123);
        for i in 0..1000 {
            let n = Field::rand(&mut rng);
            let n = Field::one();
            let m = Hash::from(n).into();
            assert_eq!(n, m);
        }
    }

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
