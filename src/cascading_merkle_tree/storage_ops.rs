use std::ops::{Deref, DerefMut, Range};

use color_eyre::{eyre::bail, Result};
use itertools::Itertools;
use rayon::prelude::*;

use crate::{
    generic_storage::GenericStorage,
    merkle_tree::{Branch, Hasher},
};

pub trait StorageOps<H>:
    GenericStorage<H::Hash>
    + Deref<Target = [H::Hash]>
    + DerefMut<Target = [H::Hash]>
    + Send
    + Sync
    + Sized
where
    H: Hasher,
{
    /// Clears the current storage and initializes it with the given leaves.
    fn populate_with_leaves(
        &mut self,
        sparse_column: &[H::Hash],
        empty_value: &H::Hash,
        leaves: &[H::Hash],
    ) {
        let num_leaves = leaves.len();
        let base_len = num_leaves.next_power_of_two();
        let storage_size = base_len << 1;
        self.clear();
        self.extend(std::iter::repeat(*empty_value).take(storage_size));
        let depth = base_len.ilog2();

        // We iterate over subsequently larger subtrees
        let mut sibling_hash = *leaves.first().unwrap_or(empty_value);
        self[1] = sibling_hash;
        for subtree_power in 1..(depth + 1) {
            let parent_index = 1 << subtree_power;
            let subtree_slice = &mut self[parent_index..(parent_index << 1)];
            let leaf_start = parent_index >> 1;
            let leaf_end = parent_index.min(num_leaves);
            let leaf_slice = &leaves[leaf_start..leaf_end];
            let root = init_subtree_with_leaves::<H>(subtree_slice, sparse_column, leaf_slice);
            let hash = H::hash_node(&sibling_hash, &root);
            self[parent_index] = hash;
            sibling_hash = hash;
        }

        self.set_num_leaves(num_leaves);
    }

    /// Returns an iterator over all leaves including those that have noe been
    /// set.
    fn leaves(&self) -> impl Iterator<Item = H::Hash> + '_ {
        self.row_indices(0)
            .take(self.num_leaves())
            .map(move |i| self[i])
    }

    fn row_indices(&self, height: usize) -> impl Iterator<Item = usize> + Send + '_ {
        let storage_height = (self.len().ilog2() - 1) as usize;
        let width = if height > storage_height {
            0
        } else {
            let height_diff = storage_height - height;
            1 << height_diff
        };
        row_indices(height).take(width)
    }

    fn row(&self, height: usize) -> impl Iterator<Item = H::Hash> + Send + '_ {
        self.row_indices(height).map(move |i| self[i])
    }

    /// Returns the root hash of the growable storage, not the top level root.
    fn storage_root(&self) -> H::Hash {
        self[self.len() >> 1]
    }

    /// Returns the depth of growable storage, not the top level root.
    fn storage_depth(&self) -> usize {
        subtree_depth(self)
    }

    /// Sets the number of leaves.
    fn set_num_leaves(&mut self, amount: usize) {
        let leaf_counter: &mut [usize] = bytemuck::cast_slice_mut(&mut self[0..1]);
        leaf_counter[0] = amount;
    }

    fn num_leaves(&self) -> usize {
        bytemuck::cast_slice(&self[0..1])[0]
    }

    /// Increments the number of leaves.
    fn increment_num_leaves(&mut self, amount: usize) {
        let leaf_counter: &mut [usize] = bytemuck::cast_slice_mut(&mut self[0..1]);
        leaf_counter[0] += amount;
    }

    /// Propagates new hashes up the top of the subtree.
    fn propagate_up(&mut self, mut index: usize) -> Option<()> {
        loop {
            let (left, right) = match sibling(index) {
                Branch::Left(sibling) => (index, sibling),
                Branch::Right(sibling) => (sibling, index),
            };
            let left_hash = self.get(left)?;
            let right_hash = self.get(right)?;
            let parent_index = parent(index);
            self[parent_index] = H::hash_node(left_hash, right_hash);
            index = parent_index;
        }
    }

    /// Validates all elements of the storage, ensuring that they
    /// correspond to a valid tree.
    fn validate(&self, empty_value: &H::Hash) -> Result<()> {
        let len = self.len();

        if !len.is_power_of_two() {
            bail!("Storage length ({len}) must be a power of 2");
        }

        if len < 2 {
            bail!("Storage length ({len}) must be greater than 1");
        }

        let width = len >> 1;
        let depth = width.ilog2() as usize;

        let num_leaves = self.num_leaves();
        let first_empty = index_from_leaf(num_leaves);

        if first_empty < len {
            self[first_empty..].par_iter().try_for_each(|hash| {
                if hash != empty_value {
                    bail!("Storage contains non-empty values past the last leaf");
                }
                Ok(())
            })?;
        }

        for height in 0..=depth {
            let row = self.row(height);
            let parents = self.row(height + 1);
            let row_couple = row.tuples();

            parents
                .zip(row_couple)
                .par_bridge()
                .try_for_each(|(parent, (left, right))| {
                    let expected = H::hash_node(&left, &right);
                    if parent != expected {
                        bail!("Invalid hash");
                    }
                    Ok(())
                })?;
        }

        Ok(())
    }
}

impl<H, S> StorageOps<H> for S
where
    H: Hasher,
    S: GenericStorage<H::Hash>,
{
}

/// Assumes that slice len is a power of 2
#[inline]
pub fn subtree_depth<H>(storage_slice: &[H]) -> usize {
    let len = storage_slice.len();

    debug_assert!(len.is_power_of_two());
    debug_assert!(len > 1);

    (len >> 1).ilog2() as usize
}

pub fn sibling(i: usize) -> Branch<usize> {
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

pub fn parent(i: usize) -> usize {
    if i.is_power_of_two() {
        return i << 1;
    }
    let prev_pow = i.next_power_of_two() >> 1;
    let shifted = i - prev_pow;
    let shifted_parent = shifted >> 1;
    shifted_parent + prev_pow
}

// leaves are 0 indexed
pub fn index_from_leaf(leaf: usize) -> usize {
    leaf + (leaf + 1).next_power_of_two()
}

pub fn leaf_from_index(index: usize) -> usize {
    let next = (index + 1).next_power_of_two();
    let prev = next >> 1;
    index - prev
}

pub fn index_height_offset(height: usize, offset: usize) -> usize {
    if offset == 0 {
        return 1 << height;
    }
    let leaf = offset * (1 << height);
    let subtree_size = (leaf + 1).next_power_of_two();
    let offset_node = leaf >> height;
    offset_node + subtree_size
}

#[cfg(test)]
pub fn children(i: usize) -> Option<(usize, usize)> {
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

/// Initialize a subtree with the given leaves in parallel.
///
/// O(n) time complexity
///
/// Subtrees are 1 indexed and directly attached to the left most branch
/// of the main tree.
///
/// This function assumes that storage is already initialized with empty
/// values and is the correct length for the subtree.
/// If 'leaves' is not long enough, the remaining leaves will be left empty
///
/// storage.len() must be a power of 2 and greater than or equal to 2
/// storage is 1 indexed
///
/// ```markdown
///           8    (subtree)
///      4      [     9     ]
///   2     5   [  10    11 ]
/// 1  3  6  7  [12 13 14 15]
///  ```
pub fn init_subtree_with_leaves<H: Hasher>(
    storage: &mut [H::Hash],
    sparse_column: &[H::Hash],
    leaves: &[H::Hash],
) -> H::Hash {
    let (_depth, width) = subtree_depth_width(storage);

    // Set the leaves
    storage[(width)..(width + leaves.len())]
        .par_iter_mut()
        .zip(leaves.par_iter())
        .for_each(|(val, leaf)| {
            *val = *leaf;
        });

    // For empty values to the right of the newly set leaves
    // we can prapogate the sparse column up the tree
    // in O(log(n)) hashes
    sparse_fill_partial_subtree::<H>(storage, sparse_column, leaves.len()..width);

    // For newly set leaves we can prapogate the hashes up the tree
    // in O(n) hashes
    propagate_partial_subtree::<H>(storage, 0..leaves.len());

    storage[1]
}

/// Extend leaves onto a preexisting subtree. This method assumes that the
/// sparse column has already been applied to all rows
///
/// O(n) time complexity
///
/// Subtrees are 1 indexed and directly attached to the left most branch
/// of the main tree.
///
/// This function assumes that storage is already initialized with empty
/// values and is the correct length for the subtree.
/// If 'leaves' is not long enough, the remaining leaves will be left empty
///
/// storage.len() must be a power of 2 and greater than or equal to 2
/// storage is 1 indexed
///
/// ```markdown
///           8    (subtree)
///      4      [     9     ]
///   2     5   [  10    11 ]
/// 1  3  6  7  [12 13 14 15]
///  ```
pub fn extend_subtree_with_leaves<H: Hasher>(
    storage: &mut [H::Hash],
    start: usize,
    leaves: &[H::Hash],
) -> H::Hash {
    let (_depth, width) = subtree_depth_width(storage);

    // Set the leaves
    storage[(width + start)..(width + start + leaves.len())]
        .par_iter_mut()
        .zip(leaves.par_iter())
        .for_each(|(val, leaf)| {
            *val = *leaf;
        });

    // For newly set leaves we can propagate the hashes up the tree
    // in O(n) hashes
    propagate_partial_subtree::<H>(storage, start..start + leaves.len());

    storage[1]
}

/// Propagate hashes up a subtree with leaves within a given range.
///
/// O(n) time complexity
///
/// Subtrees are 1 indexed and directly attached to the left most branch
/// of the main tree.
///
/// This function assumes that the tree is in a valid state except for the
/// newly added leaves.
///
/// storage.len() must be a power of 2 and greater than or equal to 2
/// storage is 1 indexed
///
/// ```markdown
///           8    (subtree)
///      4      [     9     ]
///   2     5   [  10    11 ]
/// 1  3  6  7  [12 13 14 15]
///  ```
pub fn propagate_partial_subtree<H: Hasher>(
    storage: &mut [H::Hash],
    mut range: Range<usize>,
) -> H::Hash {
    let depth = subtree_depth(storage);

    // Iterate over mutable layers of the tree
    for current_depth in (1..=depth).rev() {
        // Split the subtree into relavent layers
        let (top, child_layer) = storage.split_at_mut(1 << current_depth);
        let parent_layer = &mut top[(1 << (current_depth - 1))..];

        // Update the range to match the new parent layer
        range.start /= 2;
        range.end = ((range.end - 1) / 2) + 1;

        parent_layer[range.clone()]
            .par_iter_mut()
            .enumerate()
            .for_each(|(i, value)| {
                let i = i + range.start;
                let left = &child_layer[2 * i];
                let right = &child_layer[2 * i + 1];
                *value = H::hash_node(left, right);
            });
    }

    storage[1]
}

/// Propagates empty hashes up the tree within a given range.
///
/// O(log(n)) time complexity
///
/// Subtrees are 1 indexed and directly attached to the left most branch
/// of the main tree.
///
/// This function will overwrite any  existing or dependent values withing the
/// range. It assumes that the base layer has already been initialized with
/// empty values.
///
/// storage.len() must be a power of 2 and greater than or equal to 2
/// storage is 1 indexed
///
/// ```markdown
///           8    (subtree)
///      4      [     9     ]
///   2     5   [  10    11 ]
/// 1  3  6  7  [12 13 14 15]
///  ```
pub fn sparse_fill_partial_subtree<H: Hasher>(
    storage: &mut [H::Hash],
    sparse_column: &[H::Hash],
    mut range: Range<usize>,
) -> H::Hash {
    let depth = subtree_depth(storage);

    // Iterate over mutable layers of the tree
    for current_depth in (1..=depth).rev() {
        // Split the subtree into relavent layers
        let (top, _child_layer) = storage.split_at_mut(1 << current_depth);
        let parent_layer = &mut top[(1 << (current_depth - 1))..];

        // Update the range to match the new parent layer
        range.start /= 2;
        range.end = ((range.end - 1) / 2) + 1;

        parent_layer[range.clone()].par_iter_mut().for_each(|i| {
            *i = sparse_column[depth + 1 - current_depth];
        });
    }

    storage[1]
}

fn row_indices(height: usize) -> impl Iterator<Item = usize> + Send {
    let first = 1 << height;
    let iter_1 = first..(first + 1);

    let next = (first << 1) + 1;

    let iter_2 = (0..).scan(next, |next, i| {
        let slice_len = 1 << i;
        let res = *next..(*next + slice_len);
        *next *= 2;
        Some(res)
    });

    std::iter::once(iter_1).chain(iter_2).flatten()
}

/// Assumes that slice len is a power of 2
#[inline]
pub fn subtree_depth_width<H>(storage_slice: &[H]) -> (usize, usize) {
    let len = storage_slice.len();

    debug_assert!(len.is_power_of_two());
    debug_assert!(len > 1);

    let width = len >> 1;
    let depth = width.ilog2() as usize;

    (depth, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cascading_merkle_tree::tests::TestHasher, generic_storage::MmapVec,
        poseidon_tree::PoseidonHash,
    };

    fn test_is_storage_ops<S>(_s: &S)
    where
        S: StorageOps<PoseidonHash>,
    {
    }

    // A compile time test to verify that MmapVec is StorageOps
    #[allow(unused)]
    fn test_mmap_vec_is_storage_ops(s: MmapVec<<PoseidonHash as Hasher>::Hash>) {
        test_is_storage_ops(&s);
    }

    #[test]
    fn test_sparse_fill_partial_subtree() {
        let mut storage = vec![1; 16];
        let sparse_column = vec![1, 2, 4, 8, 16];
        sparse_fill_partial_subtree::<TestHasher>(&mut storage, &sparse_column, 4..8);
        let expected = vec![1, 8, 1, 4, 1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(storage, expected);
    }
}
