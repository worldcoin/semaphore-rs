use crate::{
    merkle_tree::{Branch, Hasher, Proof},
    util::as_bytes,
};
use std::{
    fmt::Display,
    fs::OpenOptions,
    io::Write,
    iter::{once, repeat, successors},
    ops::{Deref, DerefMut},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use mmap_rs::{MmapMut, MmapOptions};
use rayon::prelude::*;
use thiserror::Error;

pub trait VersionMarker {}
#[derive(Debug)]
pub struct Canonical;
impl VersionMarker for Canonical {}
#[derive(Debug)]
pub struct Derived;
impl VersionMarker for Derived {}

/// A dynamically growable array represented merkle tree. It has a certain
///
///           8
///     4            9
///  2     5     10     11
/// 1  3  6  7  12 13 14 15
///
/// Leaves are 0 indexed
/// 0  1  2  3  4  5  6  7
#[repr(C)]
pub struct DynamicMerkleTree<H: Hasher, V: VersionMarker = Derived> {
    depth:         usize,
    num_leaves:    usize,
    root:          H::Hash,
    empty_value:   H::Hash,
    sparse_column: Vec<H::Hash>,
    storage:       Vec<H::Hash>,
    _version:      V,
    _marker:       std::marker::PhantomData<H>,
}

// impl<H: Hasher> Display for DynamicMerkleTree<H> {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//
//     }
// }

impl<H: Hasher, Version: VersionMarker> DynamicMerkleTree<H, Version> {
    /// initial leaves populated from the given slice.
    #[must_use]
    pub fn new_with_leaves(
        depth: usize,
        empty_value: &H::Hash,
        leaves: &[H::Hash],
    ) -> DynamicMerkleTree<H, Canonical> {
        let storage = Self::storage_from_leaves(leaves, empty_value);
        let len = storage.len();
        let root = storage[len << 1];
        let sparse_column = Self::sparse_column(depth, empty_value);
        let num_leaves = leaves.len();

        DynamicMerkleTree {
            depth,
            num_leaves,
            root,
            empty_value: *empty_value,
            sparse_column,
            storage,
            _version: Canonical,
            _marker: std::marker::PhantomData,
        }
    }

    /// 0 represents the bottow later
    #[must_use]
    fn sparse_column(depth: usize, empty_value: &H::Hash) -> Vec<H::Hash> {
        // let mut column = vec![*empty_value; depth + 1];
        // let mut last = *empty_value;
        // for val in column.iter_mut().rev().skip(1) {
        //     *val = H::hash_node(&last, &last);
        //     last = *val;
        // }
        // column
        (0..depth + 1)
            .scan(*empty_value, |state, _| {
                let val = *state;
                *state = H::hash_node(&val, &val);
                Some(val)
            })
            .collect()
    }

    fn storage_from_leaves(leaves: &[H::Hash], empty_value: &H::Hash) -> Vec<H::Hash> {
        let num_leaves = leaves.len();
        let base_len = num_leaves.next_power_of_two();
        let storage_size = base_len << 1;
        let mut storage = vec![*empty_value; storage_size];
        let depth = base_len.ilog2();

        // We iterate over subsequently larger subtrees
        let mut last_sub_root = *leaves.first().unwrap_or(empty_value);
        for height in 1..(depth + 1) {
            let left_index = 1 << height;
            let storage_slice = &mut storage[left_index..(left_index << 1)];
            let leaf_start = left_index >> 1;
            let leaf_end = (leaf_start << 1).min(num_leaves);
            let leaf_slice = &leaves[leaf_start..leaf_end];
            let root = Self::init_subtree_with_leaves(storage_slice, leaf_slice);
            let hash = H::hash_node(&last_sub_root, &root);
            storage[left_index] = hash;
            last_sub_root = hash;
        }

        storage
    }

    /// Subtrees are 1 indexed and directly attached to the left most branch
    /// of the main tree.
    /// This functiona ssumes that storage is already initialized with empty
    /// values and is the correct length for the subtree.
    /// If leaves is not long enough, the remaining leaves will be left empty
    ///
    ///           8    (subtree)
    ///      4      [     9     ]
    ///   2     5   [  10    11 ]
    /// 1  3  6  7  [12 13 14 15]
    fn init_subtree_with_leaves(storage: &mut [H::Hash], leaves: &[H::Hash]) -> H::Hash {
        let num_leaves = leaves.len();
        let base_len = num_leaves.next_power_of_two();
        let depth = base_len.ilog2();

        // We iterate over mutable layers of the tree
        for current_depth in (1..=depth).rev() {
            let (top, child_layer) = storage.split_at_mut(1 << current_depth);
            let parent_layer = &mut top[(1 << (current_depth - 1))..];

            parent_layer
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, value)| {
                    let left = &child_layer[2 * i];
                    let right = &child_layer[2 * i + 1];
                    *value = H::hash_node(left, right);
                });
        }

        storage[1]
    }

    /// Assumes that storage is already initialized with empty values
    /// This is much faster than init_subtree_with_leaves
    ///
    ///           8    (subtree)
    ///      4      [     9     ]
    ///   2     5   [  10    11 ]
    /// 1  3  6  7  [12 13 14 15]
    fn init_subtree(sparse_column: &[H::Hash], storage: &mut [H::Hash]) -> H::Hash {
        let base_len = storage.len() >> 1;
        let depth = base_len.ilog2() as usize;

        // We iterate over mutable layers of the tree
        for current_depth in (1..=depth).rev() {
            let (top, child_layer) = storage.split_at_mut(1 << current_depth);
            let parent_layer = &mut top[(1 << (current_depth - 1))..];
            let parent_hash = sparse_column[depth - current_depth];

            parent_layer.par_iter_mut().for_each(|value| {
                *value = parent_hash;
            });
        }

        storage[1]
    }

    fn expand(&mut self) {
        let current_size = self.storage.len();
        self.storage
            .extend(repeat(self.empty_value).take(current_size));
        Self::init_subtree(&self.sparse_column, &mut self.storage[current_size..]);
    }

    pub fn push(&mut self, leaf: H::Hash) {
        match self.storage.get_mut(self.num_leaves + 1) {
            Some(val) => *val = leaf,
            None => {
                self.expand();
                self.storage[self.num_leaves + 1] = leaf;
            }
        }
        self.num_leaves += 1;
    }

    // pub fn extend_from_slice(&mut self, leaves: H::Hash) {
    //     match self.storage.get_many_mut.get_mut(self.num_leaves + 1) {
    //         Some(val) => *val = value,
    //         None => {
    //             self.expand();
    //             self.storage[self.num_leaves + 1] = value;
    //         }
    //     }
    //     self.num_leaves += 1;
    // }

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

    /// Returns the Merkle proof for the given leaf.
    /// Proof lengths will be `depth` long.
    #[must_use]
    pub fn proof(&self, leaf: usize) -> Proof<H> {
        let mut proof = Vec::with_capacity(self.depth);
        let storage_base = self.storage.len() >> 1;
        let storage_depth = storage_base.ilog2() as usize;

        let mut index = index_from_leaf(leaf);
        for _ in 0..storage_depth {
            let sibling = self.storage[sibling(index)];
            let branch = if index & 1 == 0 {
                // even
                Branch::Left(sibling)
            } else {
                // odd
                Branch::Right(sibling)
            };
            proof.push(branch);
            index = parent(index);
        }

        let remainder = self.sparse_column[storage_depth..]
            .iter()
            .map(|&val| Branch::Left(val));
        proof.extend(remainder);

        Proof(proof)
    }

    /// Verifies the given proof for the given value.
    #[must_use]
    pub fn verify(&self, value: H::Hash, proof: &Proof<H>) -> bool {
        proof.root(value) == self.root()
    }

    /// Returns the value at the given index.
    #[must_use]
    pub fn get_leaf(&self, leaf: usize) -> H::Hash {
        let index = index_from_leaf(leaf);
        self.storage.get(index).copied().unwrap_or(self.empty_value)
    }

    /// Returns an iterator over all leaves.
    pub fn leaves(&self) -> impl Iterator<Item = H::Hash> + '_ {
        // TODO this could be made faster by a custom iterator
        (0..(1 << self.depth())).map(|i| self.get_leaf(i))
    }
}

// impl<H: Hasher> DynamicMerkleTree<H, Canonical> {
//     /// Sets the value at the given index to the given value. This is a
// mutable     /// operation, that will modify any dense subtrees in place.
//     ///
//     /// This has potential consequences for the soundness of the whole
//     /// structure:
//     /// it has the potential to invalidate some trees that share nodes with
//     /// this one, so if many versions are kept at once, special care must be
//     /// taken when calling this. The only trees that are guaranteed to still
// be     /// valid after this operation, are those that already specify the
// same     /// value at the given index. For example, if a linear history of
// updates is     /// kept in memory, this operation is a good way to "flatten"
// updates into     /// the oldest kept version.
//     ///
//     /// This operation is useful for storage optimizations, as it avoids
//     /// allocating any new memory in dense subtrees.
//     #[must_use]
//     pub fn update_with_mutation(self, index: usize, value: &H::Hash) -> Self
// {         Self {
//             tree:     self.tree.update_with_mutation_condition(index, value,
// true),             _version: Canonical,
//         }
//     }
//
//     /// Gives a `Derived` version of this tree. Useful for initializing
//     /// versioned trees.
//     #[must_use]
//     pub fn derived(&self) -> DynamicMerkleTree<H, Derived> {
//         DynamicMerkleTree {
//             tree:     self.tree.clone(),
//             _version: Derived,
//         }
//     }
// }
//
// impl<H: Hasher> Clone for DynamicMerkleTree<H, Derived> {
//     fn clone(&self) -> Self {
//         Self {
//             tree:     self.tree.clone(),
//             _version: Derived,
//         }
//     }
// }
//
// impl<H: Hasher> AnyTree<H> {
//     fn new(depth: usize, empty_value: H::Hash) -> Self {
//         Self::Empty(EmptyTree::new(depth, empty_value))
//     }
//
//     fn new_with_dense_prefix_with_initial_values(
//         depth: usize,
//         prefix_depth: usize,
//         empty_value: &H::Hash,
//         initial_values: &[H::Hash],
//     ) -> Self {
//         assert!(depth >= prefix_depth);
//         let dense = DenseTree::new_with_values(initial_values, empty_value,
// prefix_depth);         let mut result: Self = dense.into();
//         let mut current_depth = prefix_depth;
//         while current_depth < depth {
//             result = SparseTree::new(
//                 result,
//                 EmptyTree::new(current_depth, empty_value.clone()).into(),
//             )
//             .into();
//             current_depth += 1;
//         }
//         result
//     }
//
//     fn new_with_dense_prefix(depth: usize, prefix_depth: usize, empty_value:
// &H::Hash) -> Self {         assert!(depth >= prefix_depth);
//         let mut result: Self = EmptyTree::new(prefix_depth,
// empty_value.clone())             .alloc_dense()
//             .into();
//         let mut current_depth = prefix_depth;
//         while current_depth < depth {
//             result = SparseTree::new(
//                 result,
//                 EmptyTree::new(current_depth, empty_value.clone()).into(),
//             )
//             .into();
//             current_depth += 1;
//         }
//         result
//     }
//
//     fn new_mmapped_with_dense_prefix_with_init_values(
//         depth: usize,
//         prefix_depth: usize,
//         empty_value: &H::Hash,
//         initial_values: &[H::Hash],
//         file_path: &str,
//     ) -> Result<Self, DenseMMapError> {
//         assert!(depth >= prefix_depth);
//         let dense =
//             DenseMMapTree::new_with_values(initial_values, empty_value,
// prefix_depth, file_path)?;         let mut result: Self = dense.into();
//         let mut current_depth = prefix_depth;
//         while current_depth < depth {
//             result = SparseTree::new(
//                 result,
//                 EmptyTree::new(current_depth, empty_value.clone()).into(),
//             )
//             .into();
//             current_depth += 1;
//         }
//         Ok(result)
//     }
//
//     fn try_restore_dense_mmap_tree_state(
//         depth: usize,
//         prefix_depth: usize,
//         empty_leaf: &H::Hash,
//         file_path: &str,
//     ) -> Result<Self, DenseMMapError> {
//         let dense_mmap = DenseMMapTree::attempt_restore(empty_leaf,
// prefix_depth, file_path)?;
//
//         let mut result: Self = dense_mmap.into();
//
//         let mut current_depth = prefix_depth;
//         while current_depth < depth {
//             result = SparseTree::new(
//                 result,
//                 EmptyTree::new(current_depth, empty_leaf.clone()).into(),
//             )
//             .into();
//             current_depth += 1;
//         }
//
//         Ok(result)
//     }
//
//     const fn depth(&self) -> usize {
//         match self {
//             Self::Empty(tree) => tree.depth,
//             Self::Sparse(tree) => tree.depth,
//             Self::Dense(tree) => tree.depth,
//             Self::DenseMMap(tree) => tree.depth,
//         }
//     }
//
//     fn root(&self) -> H::Hash {
//         match self {
//             Self::Empty(tree) => tree.root(),
//             Self::Sparse(tree) => tree.root(),
//             Self::Dense(tree) => tree.root(),
//             Self::DenseMMap(tree) => tree.root(),
//         }
//     }
//
//     fn proof(&self, index: usize) -> Proof<H> {
//         assert!(index < (1 << self.depth()));
//         let mut path = Vec::with_capacity(self.depth());
//         match self {
//             Self::Empty(tree) => tree.write_proof(index, &mut path),
//             Self::Sparse(tree) => tree.write_proof(index, &mut path),
//             Self::Dense(tree) => tree.write_proof(index, &mut path),
//             Self::DenseMMap(tree) => tree.write_proof(index, &mut path),
//         }
//         path.reverse();
//         Proof(path)
//     }
//
//     fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
//         match self {
//             Self::Empty(tree) => tree.write_proof(index, path),
//             Self::Sparse(tree) => tree.write_proof(index, path),
//             Self::Dense(tree) => tree.write_proof(index, path),
//             Self::DenseMMap(tree) => tree.write_proof(index, path),
//         }
//     }
//
//     fn update_with_mutation_condition(
//         &self,
//         index: usize,
//         value: &H::Hash,
//         is_mutation_allowed: bool,
//     ) -> Self {
//         match self {
//             Self::Empty(tree) => tree
//                 .update_with_mutation_condition(index, value,
// is_mutation_allowed)                 .into(),
//             Self::Sparse(tree) => tree
//                 .update_with_mutation_condition(index, value,
// is_mutation_allowed)                 .into(),
//             Self::Dense(tree) => {
//                 tree.update_with_mutation_condition(index, value,
// is_mutation_allowed)             }
//             Self::DenseMMap(tree) => {
//                 tree.update_with_mutation_condition(index, value,
// is_mutation_allowed)             }
//         }
//     }
//
//     fn get_leaf(&self, index: usize) -> H::Hash {
//         match self {
//             Self::Empty(tree) => tree.get_leaf(),
//             Self::Sparse(tree) => tree.get_leaf(index),
//             Self::Dense(tree) => tree.get_leaf(index),
//             Self::DenseMMap(tree) => tree.get_leaf(index),
//         }
//     }
// }

// leaves are 0 indexed
fn index_from_leaf(leaf: usize) -> usize {
    leaf + (leaf + 1).next_power_of_two()
}

fn parent(i: usize) -> usize {
    if i.is_power_of_two() {
        return i << 1;
    }
    let prev_pow = i.next_power_of_two() >> 1;
    let shifted = i - prev_pow;
    let shifted_parent = shifted >> 1;
    shifted_parent + prev_pow
}

fn sibling(i: usize) -> usize {
    let next_pow = i.next_power_of_two();
    if i == next_pow {
        return (i << 1) + 1;
    }
    let prev_pow = next_pow >> 1;
    if i - 1 == prev_pow {
        return prev_pow >> 1;
    }
    if i & 1 == 0 {
        // even
        i + 1
    } else {
        // odd
        i - 1
    }
}

#[cfg(test)]
mod tests {

    use ruint::uint;
    use sha2::digest::typenum::Pow;

    use crate::{poseidon_tree::PoseidonHash, Field};

    use super::*;

    struct TestHasher;
    impl Hasher for TestHasher {
        type Hash = usize;

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            left + right
        }
    }

    #[test]
    fn test_storage_from_leaves() {
        let num_leaves = 1 << 22;
        let leaves = vec![Field::default(); num_leaves];
        let empty = Field::default();
        let storage = DynamicMerkleTree::<PoseidonHash>::storage_from_leaves(&leaves, &empty);
        // println!("{storage:?}");
        // assert_eq!(storage, vec![0, 10, 3, 7, 1, 2, 3, 4]);
    }
}
