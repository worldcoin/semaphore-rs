use keccak::keccak::Keccak256;
use rand::{thread_rng, Rng};
use trees::cascading::CascadingMerkleTree;
use trees::imt::MerkleTree;
use trees::lazy::{Canonical, LazyMerkleTree};

const DEPTH: usize = 20;
const DENSE_PREFIX: usize = 16;
const EMPTY_VALUE: [u8; 32] = [0; 32];

#[test]
fn equivalent() {
    let mut lazy: LazyMerkleTree<Keccak256, Canonical> =
        LazyMerkleTree::<Keccak256, Canonical>::new_with_dense_prefix(
            DEPTH,
            DENSE_PREFIX,
            &EMPTY_VALUE,
        );
    let mut lazy_derived = lazy.derived();
    let mut imt: MerkleTree<Keccak256> = MerkleTree::new(DEPTH, EMPTY_VALUE);
    let mut cascading: CascadingMerkleTree<Keccak256> =
        CascadingMerkleTree::new(vec![], DEPTH, &EMPTY_VALUE);

    assert_eq!(lazy.root(), imt.root());
    assert_eq!(lazy.root(), cascading.root());

    let mut rng = thread_rng();

    let random_leaves = (0..1_000)
        .map(|_| rng.gen::<[u8; 32]>())
        .collect::<Vec<_>>();

    for (i, leaf) in random_leaves.iter().enumerate() {
        lazy_derived = lazy_derived.update(i, leaf);
        imt.set(i, *leaf);
        cascading.push(*leaf).unwrap();
    }

    assert_eq!(lazy_derived.root(), imt.root());
    assert_eq!(lazy_derived.root(), cascading.root());
}
