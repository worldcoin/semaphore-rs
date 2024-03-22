use crate::merkle_tree::{Branch, Hasher, Proof};
use std::iter::repeat;

use rayon::prelude::*;

pub trait VersionMarker {}
#[derive(Debug)]
pub struct Canonical;
impl VersionMarker for Canonical {}
#[derive(Debug)]
pub struct Derived;
impl VersionMarker for Derived {}

/// A dynamically growable array represented merkle tree.
///
/// ```markdown
///           8
///     4            9
///  2     5     10     11
/// 1  3  6  7  12 13 14 15
///
/// Leaves are 0 indexed
/// 0  1  2  3  4  5  6  7
#[repr(C)]
#[derive(Debug, Clone)]
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

impl<H: Hasher, Version: VersionMarker> DynamicMerkleTree<H, Version> {
    /// initial leaves populated from the given slice.
    #[must_use]
    pub fn new_with_leaves(
        depth: usize,
        empty_value: &H::Hash,
        leaves: &[H::Hash],
    ) -> DynamicMerkleTree<H, Canonical> {
        let storage = Self::storage_from_leaves(empty_value, leaves);
        let len = storage.len();
        let root = storage[len >> 1];
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

    /// Index 0 represents the bottow layer
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

    fn storage_from_leaves(empty_value: &H::Hash, leaves: &[H::Hash]) -> Vec<H::Hash> {
        let num_leaves = leaves.len();
        let base_len = num_leaves.next_power_of_two();
        let storage_size = base_len << 1;
        let mut storage = vec![*empty_value; storage_size];
        let depth = base_len.ilog2();

        // We iterate over subsequently larger subtrees
        let mut last_sub_root = *leaves.first().unwrap_or(empty_value);
        storage[1] = last_sub_root;
        for height in 1..(depth + 1) {
            let left_index = 1 << height;
            let storage_slice = &mut storage[left_index..(left_index << 1)];
            let leaf_start = left_index >> 1;
            let leaf_end = left_index.min(num_leaves);
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
    /// This function assumes that storage is already initialized with empty
    /// values and is the correct length for the subtree.
    /// If 'leaves' is not long enough, the remaining leaves will be left empty
    /// storage.len() must be a power of 2 and greater than or equal to 2
    /// storage is 1 indexed
    ///
    /// ```markdown
    ///           8    (subtree)
    ///      4      [     9     ]
    ///   2     5   [  10    11 ]
    /// 1  3  6  7  [12 13 14 15]
    fn init_subtree_with_leaves(storage: &mut [H::Hash], leaves: &[H::Hash]) -> H::Hash {
        let len = storage.len();

        debug_assert!(len.is_power_of_two());
        debug_assert!(len > 1);

        let base_len = storage.len() >> 1;
        let depth = base_len.ilog2();

        leaves.iter().enumerate().for_each(|(i, &val)| {
            storage[base_len + i] = val;
        });

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
    /// ```markdown
    ///           8    (subtree)
    ///      4      [     9     ]
    ///   2     5   [  10    11 ]
    /// 1  3  6  7  [12 13 14 15]
    fn init_subtree(sparse_column: &[H::Hash], storage: &mut [H::Hash]) -> H::Hash {
        let base_len = storage.len() >> 1;
        let depth = base_len.ilog2() as usize;

        // We iterate over mutable layers of the tree
        for current_depth in (1..=depth).rev() {
            let (top, _) = storage.split_at_mut(1 << current_depth);
            let parent_layer = &mut top[(1 << (current_depth - 1))..];
            let parent_hash = sparse_column[depth - current_depth];

            parent_layer.par_iter_mut().for_each(|value| {
                *value = parent_hash;
            });
        }

        storage[1]
    }

    fn reallocate(&mut self) {
        let current_size = self.storage.len();
        self.storage
            .extend(repeat(self.empty_value).take(current_size));
        Self::init_subtree(&self.sparse_column, &mut self.storage[current_size..]);
    }

    pub fn push(&mut self, leaf: H::Hash) {
        let index = index_from_leaf(self.num_leaves);
        match self.storage.get_mut(index) {
            Some(val) => *val = leaf,
            None => {
                self.reallocate();
                self.storage[index] = leaf;
            }
        }
        self.num_leaves += 1;
        self.propogate_up(index);
    }

    pub fn set_leaf(&mut self, leaf: usize, value: H::Hash) {
        let index = index_from_leaf(leaf);
        self.storage[index] = value;
        self.propogate_up(index);
    }

    fn propogate_up(&mut self, mut index: usize) -> Option<()> {
        loop {
            let (left, right) = match sibling(index) {
                Branch::Left(sibling) => (index, sibling),
                Branch::Right(sibling) => (sibling, index),
            };
            let left_hash = self.storage.get(left)?;
            let right_hash = self.storage.get(right)?;
            let parent_index = parent(index);
            self.storage[parent_index] = H::hash_node(left_hash, &right_hash);
            index = parent_index;
        }
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
            let sibling = self.storage[sibling(index).into_inner()];
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

fn sibling(i: usize) -> Branch<usize> {
    let next_pow = i.next_power_of_two();
    if i == next_pow {
        return Branch::Left((i << 1) + 1);
    }
    let prev_pow = next_pow >> 1;
    if i - 1 == prev_pow {
        return Branch::Right(prev_pow >> 1);
    }
    if i & 1 == 0 {
        // even
        Branch::Left(i + 1)
    } else {
        // odd
        Branch::Right(i - 1)
    }
}

fn children(i: usize) -> Option<(usize, usize)> {
    let next_pow = i.next_power_of_two();
    if i == next_pow {
        if i == 1 {
            return None;
        }
        let left = i >> 1;
        let right = i + 1;
        return Some((left, right));
    }
    let prev_pow = next_pow >> 1;
    let half = prev_pow >> 1;

    let offset = i - prev_pow;
    if offset >= half {
        return None;
    }

    let offset_left = offset * 2;
    let offset_right = offset_left + 1;

    Some((prev_pow + offset_left, prev_pow + offset_right))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Debug, Clone)]
    struct TestHasher;
    impl Hasher for TestHasher {
        type Hash = usize;

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            left + right
        }
    }

    fn debug_tree<V: VersionMarker + std::fmt::Debug>(tree: &DynamicMerkleTree<TestHasher, V>) {
        println!("{tree:?}");
        let storage_depth = tree.storage.len().ilog2();
        let storage_len = tree.storage.len();
        let root_index = storage_len >> 1;
        let mut previous = vec![root_index];
        println!("{:?}", vec![tree.storage[root_index]]);
        for _ in 1..storage_depth {
            let next = previous
                .iter()
                .flat_map(|&i| children(i))
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
            leaf_indeces.push(index_from_leaf(i));
        }
        let expected_leaves = vec![1, 3, 6, 7, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31];
        assert_eq!(leaf_indeces, expected_leaves);
        println!("Leaf indeces: {:?}", leaf_indeces);
    }

    #[test]
    fn test_parent() {
        let mut parents = Vec::new();
        for i in 1..16 {
            parents.push((i, parent(i)));
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
            siblings.push((i, sibling(i)));
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
            children.push((i, super::children(i)));
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
    fn test_storage_from_leaves() {
        let num_leaves = 1 << 3;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves(10, &empty, &leaves);
        debug_tree(&tree);
    }

    #[test]
    fn test_push() {
        let num_leaves = 1 << 3;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let mut tree = DynamicMerkleTree::<TestHasher>::new_with_leaves(10, &empty, &leaves);
        debug_tree(&tree);
        tree.push(3);
        debug_tree(&tree);
    }
}
