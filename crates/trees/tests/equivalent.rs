use poseidon::Poseidon;
use rand::{thread_rng, Rng};
use ruint::aliases::U256;
use trees::cascading::CascadingMerkleTree;
use trees::imt::MerkleTree;
use trees::lazy::{Canonical, LazyMerkleTree};

const DEPTH: usize = 20;
const DENSE_PREFIX: usize = 16;

const NUM_LEAVES: usize = 100;

type HashType = Poseidon;
const EMPTY_VALUE: U256 = U256::ZERO;

#[test]
fn equivalent() {
    let mut lazy: LazyMerkleTree<HashType, Canonical> =
        LazyMerkleTree::<HashType, Canonical>::new_with_dense_prefix(
            DEPTH,
            DENSE_PREFIX,
            &EMPTY_VALUE,
        );
    let mut lazy_derived = lazy.derived();
    let mut imt: MerkleTree<HashType> = MerkleTree::new(DEPTH, EMPTY_VALUE);
    let mut cascading: CascadingMerkleTree<HashType> =
        CascadingMerkleTree::new(vec![], DEPTH, &EMPTY_VALUE);

    assert_eq!(lazy.root(), cascading.root());
    assert_eq!(lazy.root(), imt.root());

    let mut rng = thread_rng();

    let random_leaves = (0..NUM_LEAVES)
        .map(|_| {
            let mut limbs = [0u64; 4];
            for limb in limbs.iter_mut() {
                *limb = rng.gen();
            }
            // zero last to fit in field
            limbs[3] &= 0x0FFFFFFFFFFFFFFF;

            U256::from_limbs(limbs)
        })
        .collect::<Vec<_>>();

    for (i, leaf) in random_leaves.iter().enumerate() {
        lazy_derived = lazy_derived.update(i, leaf);
        imt.set(i, *leaf);
        cascading.push(*leaf).unwrap();
    }

    // Lazy & IMT both return the total (i.e. max) number of leaves
    assert_eq!(lazy.leaves().count(), lazy_derived.leaves().count());
    assert_eq!(lazy.leaves().count(), imt.num_leaves());

    // Cascading returns the current number of leaves
    assert_eq!(cascading.num_leaves(), NUM_LEAVES);

    assert_eq!(lazy_derived.root(), cascading.root());
    assert_eq!(lazy_derived.root(), imt.root());

    // Mutably update the canonical lazy tree
    for (i, leaf) in random_leaves.iter().enumerate() {
        lazy = lazy.update_with_mutation(i, leaf);
    }

    assert_eq!(lazy.root(), cascading.root());

    for (i, leaf) in random_leaves.iter().enumerate() {
        let cascading_proof = cascading.proof(i);
        let lazy_proof = lazy.proof(i);
        let imt_proof = imt.proof(i).unwrap();

        assert_eq!(cascading_proof, lazy_proof);
        assert_eq!(cascading_proof, imt_proof);

        assert!(cascading.verify(*leaf, &cascading_proof));
        assert!(lazy.verify(*leaf, &cascading_proof));
        assert!(imt.verify(*leaf, &cascading_proof));
    }
}
