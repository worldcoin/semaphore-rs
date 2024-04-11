use std::ops::{Deref, DerefMut};

use color_eyre::eyre::{bail, ensure, Result};
use itertools::Itertools;
use rayon::prelude::*;

use crate::merkle_tree::{Branch, Hasher, Proof};

mod storage_ops;

use self::storage_ops::StorageOps;

/// A dynamically growable array represented merkle tree.
/// The left most branch of the tree consists of progressively increasing powers
/// of two. The right child of each power of two looks like a traditionally
/// indexed binary tree offset by its parent.
///
/// The underlying storage is a 1-indexed dynamically growable array that is
/// always a power of two in length. The tree is built succesively from the
/// bottom left to the top right.
///
/// The zeroth index of the underlying storage is used to store the number of
/// leaves in the tree. Because of this, the Hash used must be able to be cast
/// as a usize. If this is not possible, the code will panic at runtime.
///
/// ```markdown
///           8
///     4            9
///  2     5     10     11
/// 1  3  6  7  12 13 14 15
///
/// Leaves are 0 indexed
/// 0  1  2  3  4  5  6  7
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadingMerkleTree<H, S = Vec<<H as Hasher>::Hash>>
where
    H: Hasher,
{
    depth:         usize,
    root:          H::Hash,
    empty_value:   H::Hash,
    sparse_column: Vec<H::Hash>,
    storage:       S,
    _marker:       std::marker::PhantomData<H>,
}

impl<H, S> CascadingMerkleTree<H, S>
where
    H: Hasher,
    S: StorageOps<H>,
{
    /// Use to open a previously initialized tree
    pub fn new(
        storage: S,
        depth: usize,
        empty_value: &H::Hash,
    ) -> Result<CascadingMerkleTree<H, S>> {
        // # Safety
        // Safe because we're calling `.validate` on the tree later
        let tree = unsafe { Self::new_unchecked(storage, depth, empty_value)? };

        if !tree.storage.is_empty() {
            tree.validate()?;
        }

        Ok(tree)
    }

    /// Restores a tree from the provided storage
    ///
    /// # Safety
    /// This method is unsafe as it does not validate the contents of storage.
    /// Use this only if you're sure that the contents of storage are valid -
    /// i.e. have not been modified since last use.
    pub unsafe fn new_unchecked(
        storage: S,
        depth: usize,
        empty_value: &H::Hash,
    ) -> Result<CascadingMerkleTree<H, S>> {
        ensure!(depth > 0, "Tree depth must be greater than 0");
        if storage.is_empty() || !storage.len().is_power_of_two() {
            bail!("Storage must have been previously initialized and cannot be empty");
        }

        let sparse_column = Self::sparse_column(depth, empty_value);

        let tree = CascadingMerkleTree {
            depth,
            root: *empty_value,
            empty_value: *empty_value,
            sparse_column,
            storage,
            _marker: std::marker::PhantomData,
        };

        Ok(tree)
    }

    /// Create and initialize a tree in the provided storage
    #[must_use]
    pub fn new_with_leaves(
        mut storage: S,
        depth: usize,
        empty_value: &H::Hash,
        leaves: &[H::Hash],
    ) -> CascadingMerkleTree<H, S> {
        assert!(depth > 0, "Tree depth must be greater than 0");
        storage.populate_with_leaves(empty_value, leaves);

        let sparse_column = Self::sparse_column(depth, empty_value);

        let mut tree = CascadingMerkleTree {
            depth,
            root: *empty_value,
            empty_value: *empty_value,
            sparse_column,
            storage,
            _marker: std::marker::PhantomData,
        };

        tree.recompute_root();
        tree
    }

    /// Returns the depth of the tree.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the root of the tree.
    #[must_use]
    pub const fn root(&self) -> H::Hash {
        self.root
    }

    /// Returns the the total number of leaves that have been inserted into the
    /// tree. It's important to note that this is not the same as total
    /// capacity of leaves. Leaves that have manually been set to empty
    /// values are not considered.
    #[must_use]
    pub fn num_leaves(&self) -> usize {
        self.storage.num_leaves()
    }

    /// Sets the value at the given index.
    ///
    /// # Panics
    ///
    /// Panics if the leaf index is not less than the current
    /// number of leaves.
    pub fn set_leaf(&mut self, leaf: usize, value: H::Hash) {
        assert!(leaf < self.num_leaves(), "Leaf index out of bounds");
        let index = storage_ops::index_from_leaf(leaf);
        self.storage[index] = value;
        self.storage.propagate_up(index);
        self.recompute_root();
    }

    pub fn push(&mut self, leaf: H::Hash) -> Result<()> {
        let index = storage_ops::index_from_leaf(self.num_leaves());

        // If the index is out of bounds, we need to reallocate the storage
        // we must always have 2^n leaves for any n
        if index >= self.storage.len() {
            let next_power_of_two = (self.storage.len() + 1).next_power_of_two();
            let diff = next_power_of_two - self.storage.len();

            for _ in 0..diff {
                self.storage.push(self.empty_value);
            }
        }

        self.storage[index] = leaf;

        self.storage.increment_num_leaves(1);
        self.storage.propagate_up(index);
        self.recompute_root();
        Ok(())
    }

    /// Returns the Merkle proof for the given leaf.
    ///
    /// # Panics
    ///
    /// Panics if the leaf index is not less than the current
    /// number of leaves.
    #[must_use]
    pub fn proof(&self, leaf: usize) -> Proof<H> {
        assert!(leaf < self.num_leaves(), "Leaf index out of bounds");
        let mut proof = Vec::with_capacity(self.depth);
        let storage_depth = storage_ops::subtree_depth(&self.storage);

        let mut index = storage_ops::index_from_leaf(leaf);
        for _ in 0..storage_depth {
            match storage_ops::sibling(index) {
                Branch::Left(sibling_index) => {
                    proof.push(Branch::Left(self.storage[sibling_index]));
                }
                Branch::Right(sibling_index) => {
                    proof.push(Branch::Right(self.storage[sibling_index]));
                }
            }
            index = storage_ops::parent(index);
        }

        let remainder = self.sparse_column[storage_depth..(self.sparse_column.len() - 1)]
            .iter()
            .map(|&val| Branch::Left(val));
        proof.extend(remainder);

        Proof(proof)
    }

    /// Returns the Merkle proof for the given leaf hash.
    /// Leaves are scanned from right to left.
    /// This is a slow operation and `proof` should be used when possible.
    #[must_use]
    pub fn proof_from_hash(&self, leaf: H::Hash) -> Option<Proof<H>> {
        let leaf = self.get_leaf_from_hash(leaf)?;
        Some(self.proof(leaf))
    }

    /// Verifies the given proof for the given value.
    #[must_use]
    pub fn verify(&self, value: H::Hash, proof: &Proof<H>) -> bool {
        proof.root(value) == self.root()
    }

    /// Returns the node hash at the given index.
    ///
    /// # Panics
    ///
    /// Panics if either the depth or offset is out of bounds.
    #[must_use]
    pub fn get_node(&self, depth: usize, offset: usize) -> H::Hash {
        let height = self.depth - depth;
        let index = storage_ops::index_height_offset(height, offset);
        match self.storage.get(index) {
            Some(hash) => *hash,
            None => {
                if offset == 0 {
                    self.compute_from_storage_tip(depth)
                } else {
                    self.sparse_column[height]
                }
            }
        }
    }

    /// Returns the hash at the given leaf index.
    #[must_use]
    pub fn get_leaf(&self, leaf: usize) -> H::Hash {
        let index = storage_ops::index_from_leaf(leaf);
        self.storage.get(index).copied().unwrap_or(self.empty_value)
    }

    /// Returns the leaf index for the given leaf hash.
    #[must_use]
    pub fn get_leaf_from_hash(&self, hash: H::Hash) -> Option<usize> {
        let num_leaves = self.num_leaves();
        if num_leaves == 0 {
            return None;
        }

        let mut end = storage_ops::index_from_leaf(num_leaves - 1) + 1; // 4
        let prev_pow = end.next_power_of_two() >> 1;
        let mut start = prev_pow + (prev_pow >> 1);

        loop {
            match (start..end).rev().find(|&i| self.storage[i] == hash) {
                Some(index) => {
                    return Some(storage_ops::leaf_from_index(index));
                }
                None => {
                    if start == 1 {
                        return None;
                    }
                    start /= 2;
                    end = (start + 1).next_power_of_two();
                }
            }
        }
    }

    /// Returns an iterator over all leaf hashes.
    pub fn leaves(&self) -> impl Iterator<Item = H::Hash> + '_ {
        self.storage.leaves()
    }

    /// Returns the `sparse_column` for the given depth and empty_value.
    /// This columns represents empy values sequentially hashed together up to
    /// the top of the tree.
    /// Index 0 represents the bottom layer of the tree.
    #[must_use]
    fn sparse_column(depth: usize, empty_value: &H::Hash) -> Vec<H::Hash> {
        (0..depth + 1)
            .scan(*empty_value, |state, _| {
                let val = *state;
                *state = H::hash_node(&val, &val);
                Some(val)
            })
            .collect()
    }

    /// Returns the root of the tree.
    /// Hashes are recomputed from the storage tip.
    fn recompute_root(&mut self) -> H::Hash {
        let hash = self.compute_from_storage_tip(0);
        self.root = hash;
        hash
    }

    /// Recomputes hashess from the storage tip up to the given depth.
    /// The hash returned is the hash of the left most branch of the tree.
    fn compute_from_storage_tip(&self, depth: usize) -> H::Hash {
        let storage_root = self.storage.storage_root();
        let storage_depth = self.storage.storage_depth();
        let mut hash = storage_root;
        for i in storage_depth..(self.depth - depth) {
            hash = H::hash_node(&hash, &self.sparse_column[i]);
        }
        hash
    }

    /// Validates all elements of the storage, ensuring that they
    /// correspond to a valid tree.
    pub fn validate(&self) -> Result<()> {
        self.storage.validate(&self.empty_value)
    }

    // pub fn extend_from_slice(&mut self, leaves: &[H::Hash]) {
    //     let mut storage_len = self.storage.len();
    //     let leaf_capacity = storage_len >> 1;
    //     if self.num_leaves + leaves.len() > leaf_capacity {
    //         self.reallocate();
    //         storage_len = self.storage.len();
    //     }
    //
    //     let base_len = storage_len >> 1;
    //     let depth = base_len.ilog2();
    //
    //     let mut parents = vec![];
    //     leaves.par_iter().enumerate().for_each(|(i, &val)| {
    //         let leaf_index = self.num_leaves + i;
    //         let index = index_from_leaf(leaf_index);
    //         self.storage[index] = val;
    //         parents.push(index);
    //     });

    // leaves.iter().enumerate().for_each(|(i, &val)| {
    //     storage[base_len + i] = val;
    // });
    //
    // // We iterate over mutable layers of the tree
    // for current_depth in (1..=depth).rev() {
    //     let (top, child_layer) = storage.split_at_mut(1 <<
    // current_depth);     let parent_layer = &mut top[(1 <<
    // (current_depth - 1))..];
    //
    //     parent_layer
    //         .par_iter_mut()
    //         .enumerate()
    //         .for_each(|(i, value)| {
    //             let left = &child_layer[2 * i];
    //             let right = &child_layer[2 * i + 1];
    //             *value = H::hash_node(left, right);
    //         });
    // }
    //
    // storage[1]
    // }
}

#[cfg(test)]
mod tests {

    use serial_test::serial;

    use super::*;
    use crate::generic_storage::{GenericStorage, MmapVec};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestHasher;
    impl Hasher for TestHasher {
        type Hash = usize;

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            left + right
        }
    }

    fn debug_tree<H, S>(tree: &CascadingMerkleTree<H, S>)
    where
        H: Hasher + std::fmt::Debug,
        S: GenericStorage<H::Hash> + std::fmt::Debug,
    {
        println!("{tree:?}");
        let storage_depth = tree.storage.len().ilog2();
        let storage_len = tree.storage.len();
        let root_index = storage_len >> 1;
        let mut previous = vec![root_index];
        println!("{:?}", vec![tree.storage[root_index]]);
        for _ in 1..storage_depth {
            let next = previous
                .iter()
                .flat_map(|&i| storage_ops::children(i))
                .collect::<Vec<_>>();
            previous = next.iter().flat_map(|&(l, r)| [l, r]).collect();
            let row = previous
                .iter()
                .map(|&i| tree.storage[i])
                .collect::<Vec<_>>();
            println!("{row:?}");
        }
    }

    #[test]
    fn test_index_from_leaf() {
        let mut leaf_indeces = Vec::new();
        for i in 0..16 {
            leaf_indeces.push(storage_ops::index_from_leaf(i));
        }
        let expected_leaves = vec![1, 3, 6, 7, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31];
        assert_eq!(leaf_indeces, expected_leaves);
        println!("Leaf indeces: {:?}", leaf_indeces);
    }

    #[test]
    fn test_index_height_offset() {
        let expected = vec![
            ((0, 0), 1),
            ((0, 1), 3),
            ((0, 2), 6),
            ((0, 3), 7),
            ((0, 4), 12),
            ((0, 5), 13),
            ((0, 6), 14),
            ((0, 7), 15),
            ((1, 0), 2),
            ((1, 1), 5),
            ((1, 2), 10),
            ((1, 3), 11),
            ((2, 0), 4),
            ((2, 1), 9),
            ((3, 0), 8),
        ];
        for ((height, offset), result) in expected {
            println!(
                "Height: {}, Offset: {}, expected: {}",
                height, offset, result
            );
            assert_eq!(storage_ops::index_height_offset(height, offset), result);
        }
    }

    #[test]
    fn test_parent() {
        let mut parents = Vec::new();
        for i in 1..16 {
            parents.push((i, storage_ops::parent(i)));
        }
        let expected_parents = vec![
            (1, 2),
            (2, 4),
            (3, 2),
            (4, 8),
            (5, 4),
            (6, 5),
            (7, 5),
            (8, 16),
            (9, 8),
            (10, 9),
            (11, 9),
            (12, 10),
            (13, 10),
            (14, 11),
            (15, 11),
        ];
        assert_eq!(parents, expected_parents);
        println!("Parents: {:?}", parents);
    }

    #[test]
    fn test_sibling() {
        let mut siblings = Vec::new();
        for i in 1..16 {
            siblings.push((i, storage_ops::sibling(i)));
        }
        use Branch::*;
        let expected_siblings = vec![
            (1, Left(3)),
            (2, Left(5)),
            (3, Right(1)),
            (4, Left(9)),
            (5, Right(2)),
            (6, Left(7)),
            (7, Right(6)),
            (8, Left(17)),
            (9, Right(4)),
            (10, Left(11)),
            (11, Right(10)),
            (12, Left(13)),
            (13, Right(12)),
            (14, Left(15)),
            (15, Right(14)),
        ];
        assert_eq!(siblings, expected_siblings);
        println!("Siblings: {:?}", siblings);
    }

    #[test]
    fn test_children() {
        let mut children = Vec::new();
        for i in 1..16 {
            children.push((i, storage_ops::children(i)));
        }
        let expected_siblings = vec![
            (1, None),
            (2, Some((1, 3))),
            (3, None),
            (4, Some((2, 5))),
            (5, Some((6, 7))),
            (6, None),
            (7, None),
            (8, Some((4, 9))),
            (9, Some((10, 11))),
            (10, Some((12, 13))),
            (11, Some((14, 15))),
            (12, None),
            (13, None),
            (14, None),
            (15, None),
        ];
        assert_eq!(children, expected_siblings);
        println!("Siblings: {:?}", children);
    }

    #[should_panic]
    #[test]
    fn test_hash_too_small() {
        #[derive(Debug, Clone, PartialEq, Eq)]
        struct InvalidHasher;
        impl Hasher for InvalidHasher {
            type Hash = u32;

            fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
                left + right
            }
        }

        let _ = CascadingMerkleTree::<InvalidHasher>::new_with_leaves(vec![], 1, &0, &[]);
    }

    #[test]
    fn test_min_sized_tree() {
        let num_leaves = 1;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 1, &empty, &leaves);
        tree.validate().unwrap();
        debug_tree(&tree);
    }

    #[should_panic]
    #[test]
    fn test_zero_depth_tree() {
        let num_leaves = 1;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 0, &empty, &leaves);
        debug_tree(&tree);
    }

    #[test]
    fn test_odd_leaves() {
        let num_leaves = 5;
        let leaves = vec![1; num_leaves];
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 10, &0, &leaves);
        let expected = CascadingMerkleTree::<TestHasher> {
            depth:         10,
            root:          5,
            empty_value:   0,
            sparse_column: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            storage:       vec![5, 1, 2, 1, 4, 2, 1, 1, 5, 1, 1, 0, 1, 0, 0, 0],
            _marker:       std::marker::PhantomData,
        };
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree, expected);
    }

    #[test]
    fn test_even_leaves() {
        let num_leaves = 1 << 3;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 10, &empty, &leaves);
        let expected = CascadingMerkleTree::<TestHasher> {
            depth:         10,
            root:          8,
            empty_value:   0,
            sparse_column: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            storage:       vec![8, 1, 2, 1, 4, 2, 1, 1, 8, 4, 2, 2, 1, 1, 1, 1],
            _marker:       std::marker::PhantomData,
        };
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree, expected);
    }

    #[test]
    fn test_no_leaves() {
        let leaves = vec![];
        let empty = 0;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 10, &empty, &leaves);
        let expected = CascadingMerkleTree::<TestHasher> {
            depth:         10,
            root:          0,
            empty_value:   0,
            sparse_column: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            storage:       vec![0, 0],
            _marker:       std::marker::PhantomData,
        };
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree, expected);
    }

    #[test]
    fn test_sparse_column() {
        let leaves = vec![];
        let empty = 1;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 10, &empty, &leaves);
        let expected = CascadingMerkleTree::<TestHasher> {
            depth:         10,
            root:          1024,
            empty_value:   1,
            sparse_column: vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
            storage:       vec![0, 1],
            _marker:       std::marker::PhantomData,
        };
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree, expected);
    }

    #[test]
    fn test_compute_root() {
        let num_leaves = 1 << 3;
        let leaves = vec![0; num_leaves];
        let empty = 1;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 4, &empty, &leaves);
        let expected = CascadingMerkleTree::<TestHasher> {
            depth:         4,
            root:          8,
            empty_value:   1,
            sparse_column: vec![1, 2, 4, 8, 16],
            storage:       vec![8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            _marker:       std::marker::PhantomData,
        };
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree, expected);
    }

    #[test]
    fn test_get_node() {
        let num_leaves = 3;
        let leaves = vec![3; num_leaves];
        let empty = 1;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 3, &empty, &leaves);
        debug_tree(&tree);
        tree.validate().unwrap();
        let expected = vec![
            ((3, 0), 3),
            ((3, 1), 3),
            ((3, 2), 3),
            ((3, 3), 1),
            ((3, 4), 1),
            ((3, 5), 1),
            ((3, 6), 1),
            ((3, 7), 1),
            ((2, 0), 6),
            ((2, 1), 4),
            ((2, 2), 2),
            ((2, 3), 2),
            ((1, 0), 10),
            ((1, 1), 4),
            ((0, 0), 14),
        ];
        for ((depth, offset), result) in expected {
            println!("Depth: {}, Offset: {}, expected: {}", depth, offset, result);
            assert_eq!(tree.get_node(depth, offset), result);
        }
    }

    #[test]
    fn test_get_leaf_from_hash() {
        let empty = 0;
        let mut tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 10, &empty, &[]);
        tree.validate().unwrap();
        for i in 1..=64 {
            tree.push(i).unwrap();
            tree.validate().unwrap();
            let first = tree.get_leaf_from_hash(1).unwrap();
            let this = tree.get_leaf_from_hash(i).unwrap();
            assert_eq!(first, 0);
            assert_eq!(this, i - 1);
        }
        assert!(tree.get_leaf_from_hash(65).is_none());
    }

    #[test]
    fn test_row_indices() {
        let num_leaves = 12;
        let leaves = vec![3; num_leaves];
        let empty = 1;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 3, &empty, &leaves);
        tree.validate().unwrap();
        debug_tree(&tree);
        let expected = vec![
            (0, vec![
                1usize, 3, 6, 7, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31,
            ]),
            (1, vec![2, 5, 10, 11, 20, 21, 22, 23]),
            (2, vec![4, 9, 18, 19]),
            (3, vec![8, 17]),
            (4, vec![16]),
        ];
        for (height, result) in expected {
            println!("Height: {}, expected: {:?}", height, result);
            assert_eq!(
                <Vec<usize> as StorageOps<TestHasher>>::row_indices(&tree.storage, height)
                    .collect::<Vec<usize>>(),
                result
            );
        }
    }

    #[test]
    fn test_row() {
        let leaves = vec![1, 2, 3, 4, 5, 6];
        let empty = 0;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 20, &empty, &leaves);
        tree.validate().unwrap();
        debug_tree(&tree);
        let expected = vec![
            (0, vec![1, 2, 3, 4, 5, 6, 0, 0]),
            (1, vec![3, 7, 11, 0]),
            (2, vec![10, 11]),
            (3, vec![21]),
        ];
        for (height, result) in expected {
            println!("Height: {}, expected: {:?}", height, result);
            assert_eq!(
                <Vec<usize> as StorageOps<TestHasher>>::row(&tree.storage, height)
                    .collect::<Vec<usize>>(),
                result
            );
            // assert_eq!(tree.storage.row_indices(height).collect(), result);
        }
    }

    #[test]
    fn test_proof_from_hash() {
        let leaves = vec![1, 2, 3, 4, 5, 6];
        let empty = 1;
        let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 4, &empty, &leaves);
        debug_tree(&tree);
        tree.validate().unwrap();
        let expected = vec![
            (1, vec![
                Branch::Left(2),
                Branch::Left(7),
                Branch::Left(13),
                Branch::Left(8),
            ]),
            (2, vec![
                Branch::Right(1),
                Branch::Left(7),
                Branch::Left(13),
                Branch::Left(8),
            ]),
            (3, vec![
                Branch::Left(4),
                Branch::Right(3),
                Branch::Left(13),
                Branch::Left(8),
            ]),
            (4, vec![
                Branch::Right(3),
                Branch::Right(3),
                Branch::Left(13),
                Branch::Left(8),
            ]),
            (5, vec![
                Branch::Left(6),
                Branch::Left(2),
                Branch::Right(10),
                Branch::Left(8),
            ]),
            (6, vec![
                Branch::Right(5),
                Branch::Left(2),
                Branch::Right(10),
                Branch::Left(8),
            ]),
        ];
        for (leaf, expected_proof) in expected {
            let proof = tree.proof_from_hash(leaf).unwrap();
            assert_eq!(proof.0, expected_proof);
            assert!(tree.verify(leaf, &proof));
        }
    }

    #[test]
    fn test_push() {
        let num_leaves = 1 << 3;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let mut tree =
            CascadingMerkleTree::<TestHasher>::new_with_leaves(vec![], 22, &empty, &leaves);
        debug_tree(&tree);
        tree.validate().unwrap();
        tree.push(3).unwrap();
        debug_tree(&tree);
        tree.validate().unwrap();
    }

    #[test]
    fn test_vec_realloc_speed() {
        let empty = 0;
        let leaves = vec![1; 1 << 20];
        let mut tree =
            CascadingMerkleTree::<TestHasher, Vec<_>>::new_with_leaves(vec![], 30, &empty, &leaves);
        let start = std::time::Instant::now();
        tree.push(1).unwrap();
        let elapsed = start.elapsed();
        println!(
            "Leaf index: {}, Time: {:?}ms",
            tree.num_leaves(),
            elapsed.as_millis()
        );
    }

    #[test]
    #[serial]
    fn test_mmap_realloc_speed() {
        let empty = 0;
        let leaves = vec![1; 1 << 20];

        println!("Create tempfile");
        let tempfile = tempfile::tempfile().unwrap();
        println!("Init mmap");
        let mmap_vec: MmapVec<_> = unsafe { MmapVec::new(tempfile).unwrap() };

        println!("Init tree");
        let mut tree = CascadingMerkleTree::<TestHasher, MmapVec<_>>::new_with_leaves(
            mmap_vec, 30, &empty, &leaves,
        );

        println!("test push");
        let start = std::time::Instant::now();
        tree.push(1).unwrap();
        let elapsed = start.elapsed();
        println!(
            "Leaf index: {}, Time: {:?}ms",
            tree.num_leaves(),
            elapsed.as_millis()
        );
    }
}
