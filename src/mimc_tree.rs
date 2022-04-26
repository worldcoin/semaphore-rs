use crate::{
    hash::Hash,
    merkle_tree::{self, Hasher, MerkleTree},
    mimc_hash::hash,
};
use serde::Serialize;
use zkp_u256::U256;

pub type MimcTree = MerkleTree<MimcHash>;
#[allow(dead_code)]
pub type Branch = merkle_tree::Branch<MimcHash>;
#[allow(dead_code)]
pub type Proof = merkle_tree::Proof<MimcHash>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MimcHash;

impl Hasher for MimcHash {
    type Hash = Hash;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let left = U256::from_bytes_be(left.as_bytes_be());
        let right = U256::from_bytes_be(right.as_bytes_be());
        Hash::from_bytes_be(hash(&[left, right]).to_bytes_be())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_tree_4() {
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "1c4823575d154474ee3e5ac838d002456a815181437afd14f126da58a9912bbe"
        ));
        let tree = MimcTree::new(3, LEAF);
        assert_eq!(tree.num_leaves(), 4);
        assert_eq!(
            tree.root(),
            Hash::from_bytes_be(hex!(
                "250de92bd4bcf4fb684fdf64923cb3b20ef4118b41c6ffb8c36b606468d6be57"
            ))
        );
        let proof = tree.proof(3).expect("proof should exist");
        assert_eq!(
            proof,
            crate::merkle_tree::Proof(vec![
                Branch::Right(LEAF),
                Branch::Right(Hash::from_bytes_be(hex!(
                    "19f1cba77f27301df4ce3391f9b0d766cfd304d0f069cec6c0e55dfda6aba924"
                ))),
            ])
        );
    }
}
