use std::ops::{Deref, DerefMut};

use color_eyre::eyre::bail;
use color_eyre::Result;
use itertools::Itertools;
use rayon::prelude::*;

use crate::generic_storage::GenericStorage;
use crate::merkle_tree::{Branch, Hasher};

pub fn new_with_leaves<S, H>(gs: &mut S, empty_value: &H::Hash, leaves: &[H::Hash])
where
    H: Hasher,
    S: GenericStorage<H::Hash>,
    {
    println!("A");
    let num_leaves = leaves.len();
    let base_len = num_leaves.next_power_of_two();
    let storage_size = base_len << 1;
    let mut storage = vec![*empty_value; storage_size];
    let depth = base_len.ilog2();

    println!("B");

    // We iterate over subsequently larger subtrees
    let mut last_sub_root = *leaves.first().unwrap_or(empty_value);
    println!("C");
    storage[1] = last_sub_root;
    println!("D");
    for height in 1..(depth + 1) {
        let left_index = 1 << height;
        let storage_slice = &mut storage[left_index..(left_index << 1)];
        let leaf_start = left_index >> 1;
        let leaf_end = left_index.min(num_leaves);
        let leaf_slice = &leaves[leaf_start..leaf_end];
        let root = init_subtree_with_leaves::<H>(storage_slice, leaf_slice);
        let hash = H::hash_node(&last_sub_root, &root);
        storage[left_index] = hash;
        last_sub_root = hash;
    }

    println!("E");

    for leaf in storage {
        gs.push(leaf);
    }
    println!("F");

    <S as StorageOps<H>>::set_num_leaves(gs, num_leaves);
    println!("G");
}

pub trait StorageOps<H>:
    Deref<Target = [H::Hash]> + DerefMut<Target = [H::Hash]> + Send + Sync + Sized
where
    H: Hasher,
{
    /// Returns an iterator over all leaves including those that have noe been
    /// set.
    fn leaves(&self) -> impl Iterator<Item = H::Hash> + '_ {
        self.row_indices(0).map(move |i| self[i])
    }

    fn row_indices(&self, height: usize) -> impl Iterator<Item = usize> + Send + '_ {
        let first = 1 << height;
        let storage_len = self.len();
        let mut iters = vec![];

        if first >= storage_len {
            return iters.into_iter().flatten();
        }

        iters.push(first..(first + 1));

        let mut next = (first << 1) + 1;

        for i in 0.. {
            if next >= storage_len {
                break;
            }
            let slice_len = 1 << i;
            iters.push(next..(next + slice_len));
            next *= 2;
        }

        iters.into_iter().flatten()
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

    /// Propogates new hashes up the top of the subtree.
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

/// Assumed that slice len is a power of 2
#[inline]
pub fn subtree_depth<H>(storage_slice: &[H]) -> usize {
    let len = storage_slice.len();

    println!("len = {len}");
    debug_assert!(len.is_power_of_two());
    debug_assert!(len > 1);

    (len >> 1).ilog2() as usize
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

fn parent(i: usize) -> usize {
    if i.is_power_of_two() {
        return i << 1;
    }
    let prev_pow = i.next_power_of_two() >> 1;
    let shifted = i - prev_pow;
    let shifted_parent = shifted >> 1;
    shifted_parent + prev_pow
}

// leaves are 0 indexed
fn index_from_leaf(leaf: usize) -> usize {
    leaf + (leaf + 1).next_power_of_two()
}

/// TODO: This function is slower than necessary if the entire base of the
/// subtree is not filled with leaves.
///
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
pub fn init_subtree_with_leaves<H: Hasher>(storage: &mut [H::Hash], leaves: &[H::Hash]) -> H::Hash {
    let (depth, width) = subtree_depth_width(storage);

    storage[width..(width + leaves.len())]
        .par_iter_mut()
        .zip(leaves.par_iter())
        .for_each(|(val, leaf)| {
            *val = *leaf;
        });

    // Iterate over mutable layers of the tree
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

/// Assumed that slice len is a power of 2
#[inline]
fn subtree_depth_width<H>(storage_slice: &[H]) -> (usize, usize) {
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
    use crate::generic_storage::MmapVec;
    use crate::poseidon_tree::PoseidonHash;

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
}
