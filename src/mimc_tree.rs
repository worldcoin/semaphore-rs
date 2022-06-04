use crate::{
    hash::Hash,
    merkle_tree::{self, Hasher, MerkleTree},
    mimc_hash::hash,
};
use ruint::aliases::U256;
use serde::Serialize;

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
        let left = U256::try_from_be_slice(left.as_bytes_be()).unwrap();
        let right = U256::try_from_be_slice(right.as_bytes_be()).unwrap();
        Hash::from_bytes_be(hash(&[left, right]).to_be_bytes())
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

#[cfg(feature = "bench")]
pub mod bench {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    use criterion::{black_box, Criterion};
    use hex_literal::hex;

    // TODO: Randomize trees and indices
    // TODO: Bench over a range of depths

    const DEPTH: usize = 20;
    const LEAF: Hash = Hash::from_bytes_be(hex!(
        "352aa0818e138060d93b80393828ef8cdc104f331799b3ea647907481e51cce9"
    ));

    pub fn group(criterion: &mut Criterion) {
        bench_set(criterion);
        bench_proof(criterion);
        bench_verify(criterion);
    }

    fn bench_set(criterion: &mut Criterion) {
        let mut tree = MimcTree::new(DEPTH, LEAF);
        let index = 354_184;
        let hash = Hash::from_bytes_be([0_u8; 32]);
        criterion.bench_function("mimc_tree_set", move |bencher| {
            bencher.iter(|| tree.set(index, black_box(hash)));
        });
    }

    fn bench_proof(criterion: &mut Criterion) {
        let tree = MimcTree::new(DEPTH, LEAF);
        let index = 354_184;
        criterion.bench_function("mimc_tree_proof", move |bencher| {
            bencher.iter(|| tree.proof(black_box(index)));
        });
    }

    fn bench_verify(criterion: &mut Criterion) {
        let tree = MimcTree::new(DEPTH, LEAF);
        let index = 354_184;
        let proof = tree.proof(index).expect("proof should exist");
        let hash = Hash::from_bytes_be([0_u8; 32]);
        criterion.bench_function("mimc_verfiy", move |bencher| {
            bencher.iter(|| proof.root(black_box(hash)));
        });
    }
}
