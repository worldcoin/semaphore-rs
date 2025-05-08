use std::fmt::Debug;

use bytemuck::Pod;
use color_eyre::eyre::{ensure, Result};
use derive_where::derive_where;
use semaphore_rs_hasher::Hasher;

use crate::proof::{Branch, InclusionProof};

mod storage_ops;

use self::storage_ops::{sparse_fill_partial_subtree, StorageOps};

/// A dynamically growable array represented merkle tree.
///
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
#[derive_where(Clone; <H as Hasher>::Hash: Clone, S: Clone)]
#[derive_where(PartialEq; <H as Hasher>::Hash: PartialEq, S: PartialEq)]
#[derive_where(Eq; <H as Hasher>::Hash: Eq, S: Eq)]
#[derive_where(Debug; <H as Hasher>::Hash: Debug, S: Debug)]
pub struct CascadingMerkleTree<H, S = Vec<<H as Hasher>::Hash>>
where
    H: Hasher,
{
    depth: usize,
    root: H::Hash,
    empty_value: H::Hash,
    sparse_column: Vec<H::Hash>,
    storage: S,
    _marker: std::marker::PhantomData<H>,
}

impl<H, S> CascadingMerkleTree<H, S>
where
    H: Hasher,
    <H as Hasher>::Hash: Copy + Pod + Eq + Send + Sync,
    <H as Hasher>::Hash: Debug,
    S: StorageOps<H>,
{
    /// Use to open a previously initialized tree
    pub fn restore(
        storage: S,
        depth: usize,
        empty_value: &H::Hash,
    ) -> Result<CascadingMerkleTree<H, S>> {
        let tree = Self::restore_unchecked(storage, depth, empty_value)?;

        tree.validate()?;

        Ok(tree)
    }

    /// Restores a tree from the provided storage
    ///
    /// Invalid storage will result in unpredictable behavior
    pub fn restore_unchecked(
        storage: S,
        depth: usize,
        empty_value: &H::Hash,
    ) -> Result<CascadingMerkleTree<H, S>> {
        let len = storage.len();

        storage.validate_const()?;

        ensure!(depth > 0, "Tree depth must be greater than 0");
        ensure!(
            len <= 2usize.checked_pow(depth as u32 + 1).unwrap(),
            "Storage length must be less than or equal to 2^(depth + 1)"
        );

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

        let num_leaves = tree.num_leaves();
        ensure!(
            num_leaves <= len >> 1,
            "Number of leaves ({num_leaves}) must be less than or equal to half the storage \
             length ({len})"
        );

        Ok(tree)
    }

    /// Create and initialize a tree in the provided storage
    ///
    /// initializes an empty tree
    #[must_use]
    pub fn new(storage: S, depth: usize, empty_value: &H::Hash) -> CascadingMerkleTree<H, S> {
        Self::new_with_leaves(storage, depth, empty_value, &[])
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

        let sparse_column = Self::sparse_column(depth, empty_value);
        storage.populate_with_leaves(&sparse_column, empty_value, leaves);

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
        let storage_len = self.storage.len();

        // If the index is out of bounds, we need to reallocate the storage
        // we must always have 2^n leaves for any n
        if index >= storage_len {
            debug_assert!(storage_len.is_power_of_two());
            self.storage
                .extend(std::iter::repeat_n(self.empty_value, storage_len));
            let subtree = &mut self.storage[storage_len..(storage_len << 1)];
            sparse_fill_partial_subtree::<H>(subtree, &self.sparse_column, 0..(storage_len >> 1));
        }

        self.storage[index] = leaf;
        self.storage.increment_num_leaves(1);
        self.storage.propagate_up(index);
        self.recompute_root();

        Ok(())
    }

    /// Returns the Merkle proof for the given leaf.
    ///
    /// # TODO:
    /// Currently the branch which connects the storage tip to the root
    /// is not stored persistenetly. Repeated requests for proofs in between
    /// tree updates result in recomputing the same hashes when this could be
    /// avoided.
    ///
    /// # Panics
    ///
    /// Panics if the leaf index is not less than the current
    /// number of leaves.
    #[must_use]
    pub fn proof(&self, leaf: usize) -> InclusionProof<H> {
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

        InclusionProof(proof)
    }

    /// Returns the Merkle proof for the given leaf hash.
    /// Leaves are scanned from right to left.
    /// This is a slow operation and `proof` should be used when possible.
    #[must_use]
    pub fn proof_from_hash(&self, leaf: H::Hash) -> Option<InclusionProof<H>> {
        let leaf = self.get_leaf_from_hash(leaf)?;
        Some(self.proof(leaf))
    }

    /// Verifies the given proof for the given value.
    #[must_use]
    pub fn verify(&self, value: H::Hash, proof: &InclusionProof<H>) -> bool {
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
    /// This columns represents empty values sequentially hashed together up to
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
        debug_assert_eq!(
            self.root,
            self.compute_from_storage_tip(0),
            "Root hash does not match recomputed root hash"
        );
        self.storage.validate(&self.empty_value)
    }

    /// Extends the tree with the given leaves in parallel.
    ///
    /// ```markdown
    /// subtree_power = ilog2(8) = 3
    ///
    ///           8    (subtree)
    ///      4      [     9     ]
    ///   2     5   [  10    11 ]
    /// 1  3  6  7  [12 13 14 15]
    ///  ```
    pub fn extend_from_slice(&mut self, leaves: &[H::Hash]) {
        if leaves.is_empty() {
            return;
        }
        let num_new_leaves = leaves.len();
        let storage_len = self.storage.len();
        let current_leaves = self.num_leaves();
        let total_leaves = current_leaves + num_new_leaves;
        let new_last_leaf_index = storage_ops::index_from_leaf(total_leaves - 1);

        // If the index is out of bounds, we need to resize the storage
        // we must always have 2^n leaves for any n
        if new_last_leaf_index >= storage_len {
            let next_power_of_two = new_last_leaf_index.next_power_of_two();
            let diff = next_power_of_two - storage_len;

            self.storage
                .extend(std::iter::repeat_n(self.empty_value, diff));
        }

        // Represense the power of the first subtree that has been modified
        let first_subtree_power = ((current_leaves + 1).next_power_of_two()).ilog2();
        // Represense the power of the last subtree that has been modified
        let last_subtree_power = ((total_leaves).next_power_of_two()).ilog2();

        let mut remaining_leaves = leaves;

        // We iterate over subsequently larger subtrees which have been
        // modified by the new leaves.
        for subtree_power in first_subtree_power..=last_subtree_power {
            // We have a special case for subtree_power = 0
            // because the subtree is completely empty.
            // This represents the very bottom left of the tree.
            // parent_index represents the index of the parent node of the subtree.
            // It is the power of two on the left most branch of the tree.
            let parent_index = if subtree_power == 0 {
                let (leaf_slice, remaining) = remaining_leaves.split_at(1);
                remaining_leaves = remaining;
                self.storage[1] = leaf_slice[0];
                continue;
            } else {
                1 << subtree_power
            };

            // The slice of the storage that contains the subtree
            let subtree_slice = &mut self.storage[parent_index..(parent_index << 1)];
            let (_depth, width) = storage_ops::subtree_depth_width(subtree_slice);

            // leaf_start represents the leaf index of the subtree where we should begin
            // inserting the new leaves.
            let leaf_start = if subtree_power == first_subtree_power {
                current_leaves - ((current_leaves + 1).next_power_of_two() >> 1)
            } else {
                0
            };

            // The number of leaves to be inserted into this subtree.
            let leaves_to_take = (width - leaf_start).min(remaining_leaves.len());
            let (leaf_slice, remaining) = remaining_leaves.split_at(leaves_to_take);
            remaining_leaves = remaining;

            // Extend the subtree with the new leaves beginning at leaf_start
            let root = if leaf_start == 0 {
                storage_ops::init_subtree_with_leaves::<H>(
                    subtree_slice,
                    &self.sparse_column,
                    leaf_slice,
                )
            } else {
                storage_ops::extend_subtree_with_leaves::<H>(subtree_slice, leaf_start, leaf_slice)
            };

            // sibling_hash represents the hash of the sibling of the tip of this subtree.
            let sibling_hash = self.storage[1 << (subtree_power - 1)];

            // Update the parent node of the tip of this subtree.
            self.storage[parent_index] = H::hash_node(&sibling_hash, &root);
        }

        // Update the number of leaves in the tree.
        self.storage.set_num_leaves(total_leaves);
        self.recompute_root();
    }
}

#[cfg(test)]
mod tests {

    use rand::{thread_rng, Rng};
    use semaphore_rs_hasher::Hasher;
    use semaphore_rs_keccak::keccak::Keccak256;
    use semaphore_rs_storage::{GenericStorage, MmapVec};
    use serial_test::serial;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TestHasher;
    impl Hasher for TestHasher {
        type Hash = usize;

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            left + right
        }
    }

    pub fn debug_tree<H, S>(tree: &CascadingMerkleTree<H, S>)
    where
        H: Hasher,
        <H as Hasher>::Hash: Debug + Copy,
        S: GenericStorage<H::Hash> + std::fmt::Debug,
    {
        println!("{tree:?}");
        debug_storage::<H, S>(&tree.storage);
    }

    pub fn debug_storage<H, S>(storage: &S)
    where
        H: Hasher,
        <H as Hasher>::Hash: Debug + Copy,
        S: std::ops::Deref<Target = [<H as Hasher>::Hash]> + std::fmt::Debug,
    {
        let storage_depth = storage.len().ilog2();
        let storage_len = storage.len();
        let root_index = storage_len >> 1;
        let mut previous = vec![root_index];
        println!("{:?}", vec![storage[root_index]]);
        for _ in 1..storage_depth {
            let next = previous
                .iter()
                .flat_map(|&i| storage_ops::children(i))
                .collect::<Vec<_>>();
            previous = next.iter().flat_map(|&(l, r)| [l, r]).collect();
            let row = previous.iter().map(|&i| storage[i]).collect::<Vec<_>>();
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

    #[test]
    fn test_invalid_storage() {
        let _ = CascadingMerkleTree::<TestHasher>::restore_unchecked(vec![2, 1, 1, 1, 1], 1, &0)
            .expect_err("invalid storage len");
        let _ = CascadingMerkleTree::<TestHasher>::restore_unchecked(vec![3, 1, 1, 1], 1, &0)
            .expect_err("invalid num leaves");
        let _ =
            CascadingMerkleTree::<TestHasher>::restore_unchecked(vec![3, 1, 1, 1, 1, 1, 1], 1, &0)
                .expect_err("len too long for depth");
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
            depth: 10,
            root: 5,
            empty_value: 0,
            sparse_column: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            storage: vec![5, 1, 2, 1, 4, 2, 1, 1, 5, 1, 1, 0, 1, 0, 0, 0],
            _marker: std::marker::PhantomData,
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
            depth: 10,
            root: 8,
            empty_value: 0,
            sparse_column: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            storage: vec![8, 1, 2, 1, 4, 2, 1, 1, 8, 4, 2, 2, 1, 1, 1, 1],
            _marker: std::marker::PhantomData,
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
            depth: 10,
            root: 0,
            empty_value: 0,
            sparse_column: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            storage: vec![0, 0],
            _marker: std::marker::PhantomData,
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
            depth: 10,
            root: 1024,
            empty_value: 1,
            sparse_column: vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
            storage: vec![0, 1],
            _marker: std::marker::PhantomData,
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
            depth: 4,
            root: 8,
            empty_value: 1,
            sparse_column: vec![1, 2, 4, 8, 16],
            storage: vec![8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            _marker: std::marker::PhantomData,
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
            (
                0,
                vec![
                    1usize, 3, 6, 7, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31,
                ],
            ),
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
            (
                1,
                vec![
                    Branch::Left(2),
                    Branch::Left(7),
                    Branch::Left(13),
                    Branch::Left(8),
                ],
            ),
            (
                2,
                vec![
                    Branch::Right(1),
                    Branch::Left(7),
                    Branch::Left(13),
                    Branch::Left(8),
                ],
            ),
            (
                3,
                vec![
                    Branch::Left(4),
                    Branch::Right(3),
                    Branch::Left(13),
                    Branch::Left(8),
                ],
            ),
            (
                4,
                vec![
                    Branch::Right(3),
                    Branch::Right(3),
                    Branch::Left(13),
                    Branch::Left(8),
                ],
            ),
            (
                5,
                vec![
                    Branch::Left(6),
                    Branch::Left(2),
                    Branch::Right(10),
                    Branch::Left(8),
                ],
            ),
            (
                6,
                vec![
                    Branch::Right(5),
                    Branch::Left(2),
                    Branch::Right(10),
                    Branch::Left(8),
                ],
            ),
        ];
        for (leaf, expected_proof) in expected {
            let proof = tree.proof_from_hash(leaf).unwrap();
            assert_eq!(proof.0, expected_proof);
            assert!(tree.verify(leaf, &proof));
        }
    }

    #[test]
    fn test_leaves() {
        let mut tree = CascadingMerkleTree::<TestHasher>::new(vec![], 22, &0);
        debug_tree(&tree);
        tree.validate().unwrap();
        let expected: Vec<usize> = vec![];
        assert_eq!(tree.leaves().collect::<Vec<_>>(), expected);

        tree.push(1).unwrap();
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree.leaves().collect::<Vec<_>>(), vec![1]);

        tree.push(1).unwrap();
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree.leaves().collect::<Vec<_>>(), vec![1, 1]);

        tree.push(1).unwrap();
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree.leaves().collect::<Vec<_>>(), vec![1, 1, 1]);

        tree.push(1).unwrap();
        debug_tree(&tree);
        tree.validate().unwrap();
        assert_eq!(tree.leaves().collect::<Vec<_>>(), vec![1, 1, 1, 1]);
    }

    type Hash = <Keccak256 as Hasher>::Hash;

    #[test]
    fn test_extend_from_slice_keccak() -> color_eyre::Result<()> {
        let leaves = (0..1 << 5)
            .map(|n: u64| {
                let b = n.to_be_bytes();
                let mut hash = [0; 32];

                hash[..8].copy_from_slice(&b);

                hash
            })
            .collect::<Vec<_>>();

        // Create expected tree
        let expected_tree =
            CascadingMerkleTree::<Keccak256>::new_with_leaves(vec![], 10, &[0; 32], &leaves);

        let mut tree = CascadingMerkleTree::<Keccak256>::new(vec![], 10, &[0; 32]);
        tree.extend_from_slice(&leaves);

        assert_eq!(
            tree.leaves().collect::<Vec<Hash>>(),
            expected_tree.leaves().collect::<Vec<Hash>>()
        );

        assert_eq!(tree.root(), expected_tree.root());
        Ok(())
    }

    #[test]
    fn test_push() {
        let mut tree = CascadingMerkleTree::<TestHasher>::new(vec![], 30, &1);
        let mut vec = vec![];
        for _ in 0..300 {
            tree.push(2).unwrap();
            vec.push(2);
            debug_tree(&tree);
            tree.validate().unwrap();
            assert_eq!(tree.leaves().collect::<Vec<usize>>(), vec);
        }
    }

    #[test]
    fn test_extend_from_slice() {
        for increment in 1..20 {
            let mut tree = CascadingMerkleTree::<TestHasher>::new(vec![], 30, &1);
            let mut vec = vec![];
            for _ in 0..20 {
                tree.extend_from_slice(&vec![2; increment]);
                vec.extend_from_slice(&vec![2; increment]);
                debug_tree(&tree);
                tree.validate().unwrap();
                assert_eq!(tree.leaves().collect::<Vec<usize>>(), vec);
            }
        }
    }

    #[test]
    fn test_extend_from_slice_2() {
        for increment in 1..20 {
            let mut tree = CascadingMerkleTree::<Keccak256>::new(vec![], 30, &[0; 32]);
            let mut vec = vec![];
            for _ in 0..20 {
                let slice = (0..increment)
                    .map(|_| {
                        let mut hash = [0; 32];

                        let mut rng = thread_rng();
                        rng.fill(&mut hash);

                        hash
                    })
                    .collect::<Vec<_>>();
                tree.extend_from_slice(&slice);
                vec.extend_from_slice(&slice);
                tree.validate().unwrap();
                assert_eq!(tree.leaves().collect::<Vec<_>>(), vec);
            }
        }
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
        let mmap_vec: MmapVec<_> = unsafe { MmapVec::restore(tempfile).unwrap() };

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

    #[test]
    #[serial]
    fn test_restore_from_cache() -> color_eyre::Result<()> {
        let mut rng = rand::thread_rng();

        let leaves: Vec<Hash> = (0..1 << 2)
            .map(|_| {
                let mut hash = [0; 32];
                rng.fill(&mut hash);
                hash
            })
            .collect::<Vec<Hash>>();

        // Create a new tmp file for mmap storage
        let tempfile = tempfile::NamedTempFile::new()?;
        let file_path = tempfile.path().to_owned();

        // Initialize the expected tree
        let mmap_vec: MmapVec<_> = unsafe { MmapVec::restore(tempfile.reopen()?).unwrap() };
        let expected_tree = CascadingMerkleTree::<Keccak256, MmapVec<_>>::new_with_leaves(
            mmap_vec, 3, &[0; 32], &leaves,
        );

        let expected_root = expected_tree.root();
        let expected_leaves = expected_tree.leaves().collect::<Vec<Hash>>();

        drop(expected_tree);

        // Restore the tree
        let mmap_vec: MmapVec<_> = unsafe { MmapVec::restore_from_path(file_path).unwrap() };
        let tree = CascadingMerkleTree::<Keccak256, MmapVec<_>>::restore(mmap_vec, 3, &[0; 32])?;

        // Assert that the root and the leaves are as expected
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.leaves().collect::<Vec<Hash>>(), expected_leaves);

        Ok(())
    }
}
