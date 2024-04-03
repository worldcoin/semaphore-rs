use crate::merkle_tree::{Branch, Hasher, Proof};
use color_eyre::eyre::{bail, Result};
use itertools::Itertools;
use mmap_rs::{MmapMut, MmapOptions};
use rayon::prelude::*;
use std::{
    fs::OpenOptions,
    io::Write,
    iter::repeat,
    ops::{Deref, DerefMut},
    path::PathBuf,
};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicMerkleTree<H: Hasher, S: DynamicTreeStorage<H> = Vec<<H as Hasher>::Hash>> {
    depth:         usize,
    root:          H::Hash,
    empty_value:   H::Hash,
    sparse_column: Vec<H::Hash>,
    storage:       S,
    _marker:       std::marker::PhantomData<H>,
}

impl<H: Hasher, S: DynamicTreeStorage<H>> DynamicMerkleTree<H, S> {
    #[must_use]
    pub fn new(
        config: S::StorageConfig,
        depth: usize,
        empty_value: &H::Hash,
    ) -> DynamicMerkleTree<H, S> {
        Self::new_with_leaves(config, depth, empty_value, &[])
    }

    /// initial leaves populated from the given slice.
    #[must_use]
    pub fn new_with_leaves(
        config: S::StorageConfig,
        depth: usize,
        empty_value: &H::Hash,
        leaves: &[H::Hash],
    ) -> DynamicMerkleTree<H, S> {
        assert!(depth > 0, "Tree depth must be greater than 0");
        let storage = S::new_from_leaves(config, empty_value, leaves);
        let sparse_column = Self::sparse_column(depth, empty_value);

        let mut tree = DynamicMerkleTree {
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
        let index = index_from_leaf(leaf);
        self.storage[index] = value;
        self.storage.propogate_up(index);
        self.recompute_root();
    }

    pub fn push(&mut self, leaf: H::Hash) -> Result<()> {
        let index = index_from_leaf(self.num_leaves());
        match self.storage.get_mut(index) {
            Some(val) => *val = leaf,
            None => {
                self.storage
                    .reallocate(&self.empty_value, &self.sparse_column)?;
                self.storage[index] = leaf;
            }
        }
        self.storage.increment_num_leaves(1);
        self.storage.propogate_up(index);
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
        let storage_depth = subtree_depth(&self.storage);

        let mut index = index_from_leaf(leaf);
        for _ in 0..storage_depth {
            match sibling(index) {
                Branch::Left(sibling_index) => {
                    proof.push(Branch::Left(self.storage[sibling_index]));
                }
                Branch::Right(sibling_index) => {
                    proof.push(Branch::Right(self.storage[sibling_index]));
                }
            }
            index = parent(index);
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
        let index = index_height_offset(height, offset);
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
        let index = index_from_leaf(leaf);
        self.storage.get(index).copied().unwrap_or(self.empty_value)
    }

    /// Returns the leaf index for the given leaf hash.
    #[must_use]
    pub fn get_leaf_from_hash(&self, hash: H::Hash) -> Option<usize> {
        let num_leaves = self.num_leaves();
        if num_leaves == 0 {
            return None;
        }

        let mut end = index_from_leaf(num_leaves - 1) + 1; // 4
        let prev_pow = end.next_power_of_two() >> 1;
        let mut start = prev_pow + (prev_pow >> 1);

        loop {
            match (start..end).rev().find(|&i| self.storage[i] == hash) {
                Some(index) => {
                    return Some(leaf_from_index(index));
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

impl<H: Hasher> DynamicMerkleTree<H, MmapVec<H>> {
    /// Restores the tree from a preexisting memory map.
    pub fn restore(
        config: MmapTreeStorageConfig,
        depth: usize,
        empty_value: &H::Hash,
    ) -> Result<DynamicMerkleTree<H, MmapVec<H>>> {
        assert!(depth > 0);
        let storage = unsafe { MmapVec::restore(empty_value, config.file_path)? };
        let sparse_column = Self::sparse_column(depth, empty_value);

        let mut tree = DynamicMerkleTree {
            depth,
            root: *empty_value,
            empty_value: *empty_value,
            sparse_column,
            storage,
            _marker: std::marker::PhantomData,
        };

        tree.recompute_root();
        Ok(tree)
    }
}

// Trait for generic storage of the tree
// We require the Deref target to be a slice rather than a Vec
// so that we can have type level information that the length
// is always exactly a power of 2
pub trait DynamicTreeStorage<H: Hasher>:
    Deref<Target = [H::Hash]> + DerefMut<Target = [H::Hash]> + Send + Sync + Sized
{
    type StorageConfig;

    /// Reallocates the storage to be twice as large and fills the new
    /// storage with the empty leaf value.
    fn reallocate(&mut self, empty_value: &H::Hash, sparse_column: &[H::Hash]) -> Result<()>;

    /// Initializes the storage with the given configuration, number of leaves,
    /// and initial values.
    fn new_from_vec(
        config: Self::StorageConfig,
        num_leaves: usize,
        vec: Vec<H::Hash>,
    ) -> Result<Self>;

    fn new_from_leaves(
        config: Self::StorageConfig,
        empty_value: &H::Hash,
        leaves: &[H::Hash],
    ) -> Self {
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
            let root = init_subtree_with_leaves::<H>(storage_slice, leaf_slice);
            let hash = H::hash_node(&last_sub_root, &root);
            storage[left_index] = hash;
            last_sub_root = hash;
        }

        Self::new_from_vec(config, num_leaves, storage).unwrap()
    }

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
    fn propogate_up(&mut self, mut index: usize) -> Option<()> {
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
            bail!("Storage length must be a power of 2");
        }
        if len < 2 {
            bail!("Storage length must be greater than 1");
        }

        let width = len >> 1;
        let depth = width.ilog2() as usize;

        let num_leaves = self.num_leaves();
        let start = index_from_leaf(num_leaves);

        if start < len {
            for hash in self[start..].iter() {
                if hash != empty_value {
                    bail!("Storage contains non-empty values past the last leaf");
                }
            }
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

impl<H: Hasher> DynamicTreeStorage<H> for Vec<H::Hash> {
    type StorageConfig = ();

    fn new_from_vec(_config: (), num_leaves: usize, mut vec: Self) -> Result<Self> {
        debug_assert!(vec.len().is_power_of_two());
        <Self as DynamicTreeStorage<H>>::set_num_leaves(&mut vec, num_leaves);
        Ok(vec)
    }

    fn reallocate(&mut self, empty_value: &H::Hash, sparse_column: &[H::Hash]) -> Result<()> {
        let current_size = self.len();
        self.extend(repeat(*empty_value).take(current_size));
        init_subtree::<H>(sparse_column, &mut self[current_size..]);
        Ok(())
    }
}

/// We maintain safety by restricting the creation of configs
/// so that the caller must explicity agree to the unsafe building of
/// memory maps.
#[derive(Debug)]
pub struct MmapTreeStorageConfig {
    file_path: PathBuf,
}

impl MmapTreeStorageConfig {
    /// Creates a new memory map configuration with the given file path.
    ///
    /// # Safety
    ///
    /// The caller must ensure that only one object is assigned to a
    /// particular memory mapped file.
    pub unsafe fn new(file_path: PathBuf) -> Self {
        Self { file_path }
    }
}

impl<H: Hasher> DynamicTreeStorage<H> for MmapVec<H> {
    type StorageConfig = MmapTreeStorageConfig;

    fn new_from_vec(
        config: MmapTreeStorageConfig,
        num_leaves: usize,
        vec: Vec<H::Hash>,
    ) -> Result<Self> {
        let mut res = unsafe { Self::new(config.file_path, &vec) }?;
        res.set_num_leaves(num_leaves);
        Ok(res)
    }

    fn reallocate(&mut self, empty_value: &H::Hash, sparse_column: &[H::Hash]) -> Result<()> {
        let current_size = self.len();
        self.reallocate(empty_value)?;
        init_subtree::<H>(sparse_column, &mut self[current_size..]);
        Ok(())
    }
}

/// Memory mapped vector for dynamic merkle tree storage
pub struct MmapVec<H: Hasher> {
    mmap:      MmapMut,
    file_path: PathBuf,
    phantom:   std::marker::PhantomData<H>,
}

impl<H: Hasher> PartialEq for MmapVec<H> {
    fn eq(&self, other: &Self) -> bool {
        self.mmap.as_ref() == other.mmap.as_ref()
            && self.file_path == other.file_path
            && self.phantom == other.phantom
    }
}

impl<H: Hasher> std::fmt::Debug for MmapVec<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let slice: &[H::Hash] = bytemuck::cast_slice(self.mmap.as_slice());
        f.debug_struct("MmapVec")
            .field("mmap", &slice)
            .field("file_path", &self.file_path)
            .field("phantom", &self.phantom)
            .finish()
    }
}

impl<H: Hasher> MmapVec<H> {
    /// Creates a new memory map backed with file with provided size
    /// and fills the entire map with initial values
    ///
    /// # Safety
    ///
    /// The caller must ensure that only one memory map is assigned to a
    /// particular file
    ///
    /// # Errors
    ///
    /// - returns Err if file creation has failed
    /// - returns Err if bytes couldn't be written to file
    ///
    /// # Panics
    ///
    /// - empty hash value serialization failed
    /// - file size cannot be set
    /// - file is too large, possible truncation can occur
    /// - cannot build memory map
    pub unsafe fn new(file_path: PathBuf, storage: &[H::Hash]) -> Result<Self> {
        // Safety: potential uninitialized padding from `H::Hash` is safe to use if
        // we're casting back to the same type.
        let buf = bytemuck::cast_slice(storage);
        let buf_len = buf.len();

        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path.clone())
        {
            Ok(file) => file,
            Err(_e) => bail!("File creation failed"),
        };

        file.set_len(buf_len as u64).expect("cannot set file size");
        if file.write_all(buf).is_err() {
            bail!("Cannot write bytes to file");
        }

        let mmap = unsafe {
            MmapOptions::new(usize::try_from(buf_len as u64).expect("file size truncated"))
                .expect("cannot create memory map")
                .with_file(file, 0)
                .map_mut()
                .expect("cannot build memory map")
        };

        Ok(Self {
            mmap,
            file_path,
            phantom: std::marker::PhantomData,
        })
    }

    /// Given the file path and tree depth,
    /// it attempts to restore the memory map
    ///
    /// # Safety
    ///
    /// The caller must ensure that only one memory map is assigned to a
    /// particular file
    ///
    /// # Errors
    ///
    /// - returns Err if file doesn't exist
    /// - returns Err if file size doesn't match the expected tree size
    ///
    /// # Panics
    ///
    /// - cannot get file metadata to check for file length
    /// - truncated file size when attempting to build memory map
    /// - cannot build memory map
    pub unsafe fn restore(empty_value: &H::Hash, file_path: PathBuf) -> Result<Self> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path.clone())
        {
            Ok(file) => file,
            Err(_e) => bail!("File doesn't exist"),
        };

        let file_size = file.metadata().expect("cannot get file metadata").len();
        let size_of_empty_value = std::mem::size_of_val(empty_value);
        if !(file_size / size_of_empty_value as u64).is_power_of_two() {
            bail!("File size should be a power of 2");
        }

        let mmap = unsafe {
            MmapOptions::new(file_size as usize)
                .expect("cannot create memory map")
                .with_file(file, 0)
                .map_mut()
                .expect("cannot build memory map")
        };

        Ok(Self {
            mmap,
            file_path,
            phantom: std::marker::PhantomData,
        })
    }

    pub fn reallocate(&mut self, empty_value: &H::Hash) -> Result<()> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.file_path.clone())
        {
            Ok(file) => file,
            Err(_e) => bail!("File doesn't exist"),
        };

        let file_size = file.metadata().expect("cannot get file metadata").len();
        let size_of_empty_value = std::mem::size_of_val(empty_value);
        if !(file_size / size_of_empty_value as u64).is_power_of_two() {
            bail!("File size should be a power of 2");
        }

        let new_file_size = file_size << 1;
        file.set_len(new_file_size).expect("cannot expand size");

        self.mmap = unsafe {
            MmapOptions::new(new_file_size as usize)
                .expect("cannot create memory map")
                .with_file(file, 0)
                .map_mut()
                .expect("cannot build memory map")
        };

        let len = self.len();
        self[(len >> 1)..].par_iter_mut().for_each(|val| {
            *val = *empty_value;
        });

        Ok(())
    }
}

impl<H: Hasher> Deref for MmapVec<H> {
    type Target = [H::Hash];

    fn deref(&self) -> &Self::Target {
        bytemuck::cast_slice(self.mmap.as_slice())
    }
}

impl<H: Hasher> DerefMut for MmapVec<H> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        bytemuck::cast_slice_mut(self.mmap.as_mut_slice())
    }
}

// leaves are 0 indexed
fn index_from_leaf(leaf: usize) -> usize {
    leaf + (leaf + 1).next_power_of_two()
}

fn leaf_from_index(index: usize) -> usize {
    let next = (index + 1).next_power_of_two();
    let prev = next >> 1;
    index - prev
}

fn index_height_offset(height: usize, offset: usize) -> usize {
    if offset == 0 {
        return 1 << height;
    }
    let leaf = offset * (1 << height);
    let subtree_size = (leaf + 1).next_power_of_two();
    let offset_node = leaf >> height;
    offset_node + subtree_size
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

fn _children(i: usize) -> Option<(usize, usize)> {
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

/// Assumed that slice len is a power of 2
#[inline]
fn subtree_depth<H>(storage_slice: &[H]) -> usize {
    let len = storage_slice.len();

    debug_assert!(len.is_power_of_two());
    debug_assert!(len > 1);

    (len >> 1).ilog2() as usize
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

/// Assumes that storage is already initialized with empty values
///
/// O(log(n)) time complexity
///
/// Subtrees are 1 indexed and directly attached to the left most branch
/// of the main tree.
///
/// storage.len() must be a power of 2 and greater than or equal to 2
/// storage is 1 indexed
///
/// ```markdown
///           8    (subtree)
///      4      [     9     ]
///   2     5   [  10    11 ]
/// 1  3  6  7  [12 13 14 15]
fn init_subtree<H: Hasher>(sparse_column: &[H::Hash], storage_slice: &mut [H::Hash]) -> H::Hash {
    let depth = subtree_depth(storage_slice);

    for current_depth in 0..depth {
        let start = 1 << current_depth;
        let row = &mut storage_slice[start..(start << 1)];
        let hash = sparse_column[depth - current_depth];
        row.par_iter_mut().for_each(|value| {
            *value = hash;
        });
    }

    storage_slice[1]
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
fn init_subtree_with_leaves<H: Hasher>(storage: &mut [H::Hash], leaves: &[H::Hash]) -> H::Hash {
    let (depth, width) = subtree_depth_width(storage);

    leaves.iter().enumerate().for_each(|(i, &val)| {
        storage[width + i] = val;
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

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestHasher;
    impl Hasher for TestHasher {
        type Hash = usize;

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            left + right
        }
    }

    fn debug_tree<H: Hasher + std::fmt::Debug, S: DynamicTreeStorage<H> + std::fmt::Debug>(
        tree: &DynamicMerkleTree<H, S>,
    ) {
        println!("{tree:?}");
        let storage_depth = tree.storage.len().ilog2();
        let storage_len = tree.storage.len();
        let root_index = storage_len >> 1;
        let mut previous = vec![root_index];
        println!("{:?}", vec![tree.storage[root_index]]);
        for _ in 1..storage_depth {
            let next = previous
                .iter()
                .flat_map(|&i| _children(i))
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
            assert_eq!(index_height_offset(height, offset), result);
        }
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
            children.push((i, super::_children(i)));
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
        let _ = DynamicMerkleTree::<InvalidHasher>::new_with_leaves((), 1, &0, &[]);
    }

    #[test]
    fn test_min_sized_tree() {
        let num_leaves = 1;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 1, &empty, &leaves);
        tree.validate().unwrap();
        debug_tree(&tree);
    }

    #[should_panic]
    #[test]
    fn test_zero_depth_tree() {
        let num_leaves = 1;
        let leaves = vec![1; num_leaves];
        let empty = 0;
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 0, &empty, &leaves);
        debug_tree(&tree);
    }

    #[test]
    fn test_odd_leaves() {
        let num_leaves = 5;
        let leaves = vec![1; num_leaves];
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 10, &0, &leaves);
        let expected = DynamicMerkleTree::<TestHasher> {
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
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 10, &empty, &leaves);
        let expected = DynamicMerkleTree::<TestHasher> {
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
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 10, &empty, &leaves);
        let expected = DynamicMerkleTree::<TestHasher> {
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
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 10, &empty, &leaves);
        let expected = DynamicMerkleTree::<TestHasher> {
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
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 4, &empty, &leaves);
        let expected = DynamicMerkleTree::<TestHasher> {
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
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 3, &empty, &leaves);
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
        let mut tree = DynamicMerkleTree::<TestHasher>::new((), 10, &empty);
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
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 3, &empty, &leaves);
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
                <Vec<usize> as DynamicTreeStorage<TestHasher>>::row_indices(&tree.storage, height)
                    .collect::<Vec<usize>>(),
                result
            );
        }
    }

    #[test]
    fn test_row() {
        let leaves = vec![1, 2, 3, 4, 5, 6];
        let empty = 0;
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 20, &empty, &leaves);
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
                <Vec<usize> as DynamicTreeStorage<TestHasher>>::row(&tree.storage, height)
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
        let tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 4, &empty, &leaves);
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
        let mut tree = DynamicMerkleTree::<TestHasher>::new_with_leaves((), 22, &empty, &leaves);
        debug_tree(&tree);
        tree.validate().unwrap();
        tree.push(3).unwrap();
        debug_tree(&tree);
        tree.validate().unwrap();
    }

    #[test]

    fn test_mmap() {
        let leaves = vec![3; 3];
        let empty = 1;
        let mut tree = DynamicMerkleTree::<TestHasher, MmapVec<_>>::new_with_leaves(
            unsafe { MmapTreeStorageConfig::new(PathBuf::from("target/tmp/test.mmap")) },
            20,
            &empty,
            &leaves,
        );
        debug_tree(&tree);
        tree.validate().unwrap();

        for _ in 0..100 {
            tree.push(3).unwrap();
            tree.validate().unwrap();

            let restored = unsafe {
                DynamicMerkleTree::<TestHasher, MmapVec<_>>::restore(
                    MmapTreeStorageConfig::new(PathBuf::from("target/tmp/test.mmap")),
                    20,
                    &empty,
                )
                .unwrap()
            };
            restored.validate().unwrap();
            assert_eq!(tree, restored);
        }
    }

    #[test]
    fn test_vec_realloc_speed() {
        let empty = 0;
        let leaves = vec![1; 1 << 20];
        let mut tree =
            DynamicMerkleTree::<TestHasher, Vec<_>>::new_with_leaves((), 30, &empty, &leaves);
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
    fn test_mmap_realloc_speed() {
        let empty = 0;
        let leaves = vec![1; 1 << 20];
        let config = MmapTreeStorageConfig {
            file_path: PathBuf::from("target/tmp/test.mmap"),
        };
        let mut tree = DynamicMerkleTree::<TestHasher, MmapVec<_>>::new_with_leaves(
            config, 30, &empty, &leaves,
        );
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
