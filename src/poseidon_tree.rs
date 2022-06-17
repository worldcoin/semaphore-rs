use crate::{
    merkle_tree::{self, Hasher, MerkleTree},
    poseidon, Field,
};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub type PoseidonTree = MerkleTree<PoseidonHash>;
#[allow(dead_code)]
pub type Branch = merkle_tree::Branch<PoseidonHash>;
#[allow(dead_code)]
pub type Proof = merkle_tree::Proof<PoseidonHash>;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonHash;

impl Hasher for PoseidonHash {
    type Hash = Field;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        poseidon::hash2(*left, *right)
    }
}

#[cfg(test)]
pub mod test {

    // TODO: proptest
    // #[test]
    // fn test_ark_hash_ark_roundtrip() {
    //     let mut rng = ChaChaRng::seed_from_u64(123);
    //     for _ in 0..1000 {
    //         let n = Field::rand(&mut rng);
    //         let m = Hash::from(n).into();
    //         assert_eq!(n, m);
    //     }
    // }

    // TODO: Const constructor
    // #[test]
    // fn test_tree_4() {
    //     const LEAF: Hash = Hash::from_bytes_be(hex!(
    //         "0000000000000000000000000000000000000000000000000000000000000000"
    //     ));

    //     let tree = PoseidonTree::new(3, LEAF);
    //     assert_eq!(tree.num_leaves(), 4);
    //     assert_eq!(
    //         tree.root(),
    //         Hash::from_bytes_be(hex!(
    //
    // "1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1"
    //         ))
    //     );
    //     let proof = tree.proof(3).expect("proof should exist");
    //     assert_eq!(
    //         proof,
    //         crate::merkle_tree::Proof(vec![
    //             Branch::Right(LEAF),
    //             Branch::Right(Hash::from_bytes_be(hex!(
    //
    // "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"
    //             ))),
    //         ])
    //     );
    // }
}
