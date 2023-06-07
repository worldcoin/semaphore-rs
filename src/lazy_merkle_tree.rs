use crate::merkle_tree::{Branch, Hasher, Proof};
use std::{
    fs::OpenOptions,
    io::Write,
    iter::{once, repeat, successors},
    ops::{Deref, DerefMut},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use bincode::serialize;
use mmap_rs::{MmapMut, MmapOptions};
use thiserror::Error;

pub trait VersionMarker {}
#[derive(Debug)]
pub struct Canonical;
impl VersionMarker for Canonical {}
#[derive(Debug)]
pub struct Derived;
impl VersionMarker for Derived {}

/// A storage-optimized merkle tree. It has a certain linear-buffer represented
/// prefix subtree and the rest of the tree is represented using lazy,
/// pointer-based structures. This makes it possible to hold even large trees in
/// memory, assuming only a relatively small subset is ever modified.
///
/// It exposes an immutable API, so that multiple versions can be kept in memory
/// while reusing as much structure as possible.
///
/// The update method also allows the specification of a mutability hint, which
/// can be used to vastly improve storage characteristics, but also requires the
/// caller to ensure certain additional invariants hold. See
/// [`LazyMerkleTree::update_with_mutation`] for details.
pub struct LazyMerkleTree<H: Hasher, V: VersionMarker = Derived> {
    tree:     AnyTree<H>,
    _version: V,
}

impl<H: Hasher, Version: VersionMarker> LazyMerkleTree<H, Version> {
    /// Creates a new, fully lazy (without any dense prefix) tree.
    #[must_use]
    pub fn new(depth: usize, empty_value: H::Hash) -> LazyMerkleTree<H, Canonical> {
        LazyMerkleTree {
            tree:     AnyTree::new(depth, empty_value),
            _version: Canonical,
        }
    }

    /// Creates a new tree with a dense prefix of the given depth.
    #[must_use]
    pub fn new_with_dense_prefix(
        depth: usize,
        prefix_depth: usize,
        empty_value: &H::Hash,
    ) -> LazyMerkleTree<H, Canonical> {
        LazyMerkleTree {
            tree:     AnyTree::new_with_dense_prefix(depth, prefix_depth, empty_value),
            _version: Canonical,
        }
    }

    /// Creates a new tree with a dense prefix of the given depth, and with
    /// initial leaves populated from the given slice.
    #[must_use]
    pub fn new_with_dense_prefix_with_initial_values(
        depth: usize,
        prefix_depth: usize,
        empty_value: &H::Hash,
        initial_values: &[H::Hash],
    ) -> LazyMerkleTree<H, Canonical> {
        LazyMerkleTree {
            tree:     AnyTree::new_with_dense_prefix_with_initial_values(
                depth,
                prefix_depth,
                empty_value,
                initial_values,
            ),
            _version: Canonical,
        }
    }

    /// Creates a new memory mapped file specified by path and creates a tree
    /// with dense prefix of the given depth with initial values
    #[must_use]
    pub fn new_mmapped_with_dense_prefix_with_init_values(
        depth: usize,
        prefix_depth: usize,
        empty_value: &H::Hash,
        initial_values: &[H::Hash],
        file_path: &str,
    ) -> Result<LazyMerkleTree<H, Canonical>, DenseMMapError> {
        Ok(LazyMerkleTree {
            tree:     AnyTree::new_mmapped_with_dense_prefix_with_init_values(
                depth,
                prefix_depth,
                empty_value,
                initial_values,
                file_path,
            )?,
            _version: Canonical,
        })
    }

    /// Attempts to restore previous tree state from memory mapped file
    ///
    /// # Errors
    /// - dense mmap tree restore failed
    pub fn attempt_dense_mmap_restore(
        empty_leaf: &H::Hash,
        depth: usize,
        file_path: &str,
    ) -> Result<LazyMerkleTree<H, Canonical>, DenseMMapError> {
        Ok(LazyMerkleTree {
            tree:     match AnyTree::try_restore_dense_mmap_tree_state(empty_leaf, depth, file_path)
            {
                Ok(tree) => tree,
                Err(e) => return Err(e),
            },
            _version: Canonical,
        })
    }

    /// Returns the depth of the tree.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.tree.depth()
    }

    /// Returns the root of the tree.
    #[must_use]
    pub fn root(&self) -> H::Hash {
        self.tree.root()
    }

    /// Sets the value at the given index to the given value. This is fully
    /// immutable, returning a new tree and leaving the old one unchanged.
    /// Reuses as much memory as possible, allocating only `depth` nodes.
    #[must_use]
    pub fn update(&self, index: usize, value: &H::Hash) -> LazyMerkleTree<H, Derived> {
        LazyMerkleTree {
            tree:     self
                .tree
                .update_with_mutation_condition(index, value, false),
            _version: Derived,
        }
    }

    /// Returns the Merkle proof for the given index.
    #[must_use]
    pub fn proof(&self, index: usize) -> Proof<H> {
        self.tree.proof(index)
    }

    /// Verifies the given proof for the given value.
    #[must_use]
    pub fn verify(&self, value: H::Hash, proof: &Proof<H>) -> bool {
        proof.root(value) == self.root()
    }

    /// Returns the value at the given index.
    #[must_use]
    pub fn get_leaf(&self, index: usize) -> H::Hash {
        self.tree.get_leaf(index)
    }

    /// Returns an iterator over all leaves.
    pub fn leaves(&self) -> impl Iterator<Item = H::Hash> + '_ {
        // TODO this could be made faster by a custom iterator
        (0..(1 << self.depth())).map(|i| self.get_leaf(i))
    }
}

impl<H: Hasher> LazyMerkleTree<H, Canonical> {
    /// Sets the value at the given index to the given value. This is a mutable
    /// operation, that will modify any dense subtrees in place.
    ///
    /// This has potential consequences for the soundness of the whole
    /// structure:
    /// it has the potential to invalidate some trees that share nodes with
    /// this one, so if many versions are kept at once, special care must be
    /// taken when calling this. The only trees that are guaranteed to still be
    /// valid after this operation, are those that already specify the same
    /// value at the given index. For example, if a linear history of updates is
    /// kept in memory, this operation is a good way to "flatten" updates into
    /// the oldest kept version.
    ///
    /// This operation is useful for storage optimizations, as it avoids
    /// allocating any new memory in dense subtrees.
    #[must_use]
    pub fn update_with_mutation(self, index: usize, value: &H::Hash) -> Self {
        Self {
            tree:     self.tree.update_with_mutation_condition(index, value, true),
            _version: Canonical,
        }
    }

    /// Gives a `Derived` version of this tree. Useful for initializing
    /// versioned trees.
    #[must_use]
    pub fn derived(&self) -> LazyMerkleTree<H, Derived> {
        LazyMerkleTree {
            tree:     self.tree.clone(),
            _version: Derived,
        }
    }
}

impl<H: Hasher> Clone for LazyMerkleTree<H, Derived> {
    fn clone(&self) -> Self {
        Self {
            tree:     self.tree.clone(),
            _version: Derived,
        }
    }
}

enum AnyTree<H: Hasher> {
    Empty(EmptyTree<H>),
    Sparse(SparseTree<H>),
    Dense(DenseTree<H>),
    DenseMMap(DenseMMapTree<H>),
}

impl<H: Hasher> AnyTree<H> {
    fn new(depth: usize, empty_value: H::Hash) -> Self {
        Self::Empty(EmptyTree::new(depth, empty_value))
    }

    fn new_with_dense_prefix_with_initial_values(
        depth: usize,
        prefix_depth: usize,
        empty_value: &H::Hash,
        initial_values: &[H::Hash],
    ) -> Self {
        assert!(depth >= prefix_depth);
        let dense = DenseTree::new_with_values(initial_values, empty_value, prefix_depth);
        let mut result: Self = dense.into();
        let mut current_depth = prefix_depth;
        while current_depth < depth {
            result = SparseTree::new(
                result,
                EmptyTree::new(current_depth, empty_value.clone()).into(),
            )
            .into();
            current_depth += 1;
        }
        result
    }

    fn new_with_dense_prefix(depth: usize, prefix_depth: usize, empty_value: &H::Hash) -> Self {
        assert!(depth >= prefix_depth);
        let mut result: Self = EmptyTree::new(prefix_depth, empty_value.clone())
            .alloc_dense()
            .into();
        let mut current_depth = prefix_depth;
        while current_depth < depth {
            result = SparseTree::new(
                result,
                EmptyTree::new(current_depth, empty_value.clone()).into(),
            )
            .into();
            current_depth += 1;
        }
        result
    }

    fn new_mmapped_with_dense_prefix_with_init_values(
        depth: usize,
        prefix_depth: usize,
        empty_value: &H::Hash,
        initial_values: &[H::Hash],
        file_path: &str,
    ) -> Result<Self, DenseMMapError> {
        assert!(depth >= prefix_depth);
        let dense =
            DenseMMapTree::new_with_values(initial_values, empty_value, prefix_depth, file_path)?;
        let mut result: Self = dense.into();
        let mut current_depth = prefix_depth;
        while current_depth < depth {
            result = SparseTree::new(
                result,
                EmptyTree::new(current_depth, empty_value.clone()).into(),
            )
            .into();
            current_depth += 1;
        }
        Ok(result)
    }

    fn try_restore_dense_mmap_tree_state(
        empty_leaf: &H::Hash,
        depth: usize,
        file_path: &str,
    ) -> Result<Self, DenseMMapError> {
        let dense_mmap = DenseMMapTree::attempt_restore(empty_leaf, depth, file_path)?;

        let result: Self = dense_mmap.into();
        Ok(result)
    }

    const fn depth(&self) -> usize {
        match self {
            Self::Empty(tree) => tree.depth,
            Self::Sparse(tree) => tree.depth,
            Self::Dense(tree) => tree.depth,
            Self::DenseMMap(tree) => tree.depth,
        }
    }

    fn root(&self) -> H::Hash {
        match self {
            Self::Empty(tree) => tree.root(),
            Self::Sparse(tree) => tree.root(),
            Self::Dense(tree) => tree.root(),
            Self::DenseMMap(tree) => tree.root(),
        }
    }

    fn proof(&self, index: usize) -> Proof<H> {
        assert!(index < (1 << self.depth()));
        let mut path = Vec::with_capacity(self.depth());
        match self {
            Self::Empty(tree) => tree.write_proof(index, &mut path),
            Self::Sparse(tree) => tree.write_proof(index, &mut path),
            Self::Dense(tree) => tree.write_proof(index, &mut path),
            Self::DenseMMap(tree) => tree.write_proof(index, &mut path),
        }
        path.reverse();
        Proof(path)
    }

    fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
        match self {
            Self::Empty(tree) => tree.write_proof(index, path),
            Self::Sparse(tree) => tree.write_proof(index, path),
            Self::Dense(tree) => tree.write_proof(index, path),
            Self::DenseMMap(tree) => tree.write_proof(index, path),
        }
    }

    fn update_with_mutation_condition(
        &self,
        index: usize,
        value: &H::Hash,
        is_mutation_allowed: bool,
    ) -> Self {
        match self {
            Self::Empty(tree) => tree
                .update_with_mutation_condition(index, value, is_mutation_allowed)
                .into(),
            Self::Sparse(tree) => tree
                .update_with_mutation_condition(index, value, is_mutation_allowed)
                .into(),
            Self::Dense(tree) => {
                tree.update_with_mutation_condition(index, value, is_mutation_allowed)
            }
            Self::DenseMMap(tree) => {
                tree.update_with_mutation_condition(index, value, is_mutation_allowed)
            }
        }
    }

    fn get_leaf(&self, index: usize) -> H::Hash {
        match self {
            Self::Empty(tree) => tree.get_leaf(),
            Self::Sparse(tree) => tree.get_leaf(index),
            Self::Dense(tree) => tree.get_leaf(index),
            Self::DenseMMap(tree) => tree.get_leaf(index),
        }
    }
}

impl<H: Hasher> Clone for AnyTree<H> {
    fn clone(&self) -> Self {
        match self {
            Self::Empty(t) => t.clone().into(),
            Self::Sparse(t) => t.clone().into(),
            Self::Dense(t) => t.clone().into(),
            Self::DenseMMap(t) => t.clone().into(),
        }
    }
}

impl<H: Hasher> From<EmptyTree<H>> for AnyTree<H> {
    fn from(tree: EmptyTree<H>) -> Self {
        Self::Empty(tree)
    }
}

impl<H: Hasher> From<SparseTree<H>> for AnyTree<H> {
    fn from(tree: SparseTree<H>) -> Self {
        Self::Sparse(tree)
    }
}

impl<H: Hasher> From<DenseTree<H>> for AnyTree<H> {
    fn from(tree: DenseTree<H>) -> Self {
        Self::Dense(tree)
    }
}

impl<H: Hasher> From<DenseMMapTree<H>> for AnyTree<H> {
    fn from(tree: DenseMMapTree<H>) -> Self {
        Self::DenseMMap(tree)
    }
}

struct EmptyTree<H: Hasher> {
    depth:             usize,
    empty_tree_values: Arc<Vec<H::Hash>>,
}

impl<H: Hasher> Clone for EmptyTree<H> {
    fn clone(&self) -> Self {
        Self {
            depth:             self.depth,
            empty_tree_values: self.empty_tree_values.clone(),
        }
    }
}

impl<H: Hasher> EmptyTree<H> {
    #[must_use]
    fn new(depth: usize, empty_value: H::Hash) -> Self {
        let empty_tree_values = {
            let values = successors(Some(empty_value), |value| Some(H::hash_node(value, value)))
                .take(depth + 1)
                .collect();
            Arc::new(values)
        };
        Self {
            depth,
            empty_tree_values,
        }
    }

    fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
        for depth in (1..=self.depth).rev() {
            let val = self.empty_tree_values[depth - 1].clone();
            let branch = if get_turn_at_depth(index, depth) == Turn::Left {
                Branch::Left(val)
            } else {
                Branch::Right(val)
            };
            path.push(branch);
        }
    }

    #[must_use]
    fn update_with_mutation_condition(
        &self,
        index: usize,
        value: &H::Hash,
        is_mutation_allowed: bool,
    ) -> SparseTree<H> {
        self.alloc_sparse()
            .update_with_mutation_condition(index, value, is_mutation_allowed)
    }

    #[must_use]
    fn alloc_sparse(&self) -> SparseTree<H> {
        if self.depth == 0 {
            SparseTree::new_leaf(self.root())
        } else {
            let next_child: Self = Self {
                depth:             self.depth - 1,
                empty_tree_values: self.empty_tree_values.clone(),
            };
            SparseTree::new(next_child.clone().into(), next_child.into())
        }
    }

    #[must_use]
    fn alloc_dense(&self) -> DenseTree<H> {
        let values = self
            .empty_tree_values
            .iter()
            .rev()
            .enumerate()
            .flat_map(|(depth, value)| repeat(value).take(1 << depth));
        let padded_values = once(&self.empty_tree_values[0])
            .chain(values)
            .cloned()
            .collect();
        DenseTree {
            depth:      self.depth,
            root_index: 1,
            storage:    Arc::new(Mutex::new(padded_values)),
        }
    }

    #[must_use]
    fn root(&self) -> H::Hash {
        self.empty_tree_values[self.depth].clone()
    }

    fn get_leaf(&self) -> H::Hash {
        self.empty_tree_values[0].clone()
    }
}

struct Children<H: Hasher> {
    left:  Arc<AnyTree<H>>,
    right: Arc<AnyTree<H>>,
}

impl<H: Hasher> Clone for Children<H> {
    fn clone(&self) -> Self {
        Self {
            left:  self.left.clone(),
            right: self.right.clone(),
        }
    }
}

struct SparseTree<H: Hasher> {
    depth:    usize,
    root:     H::Hash,
    children: Option<Children<H>>,
}

#[derive(Debug, PartialEq, Eq)]
enum Turn {
    Left,
    Right,
}

const fn get_turn_at_depth(index: usize, depth: usize) -> Turn {
    if index & (1 << (depth - 1)) == 0 {
        Turn::Left
    } else {
        Turn::Right
    }
}

const fn clear_turn_at_depth(index: usize, depth: usize) -> usize {
    index & !(1 << (depth - 1))
}

impl<H: Hasher> From<Children<H>> for SparseTree<H> {
    fn from(children: Children<H>) -> Self {
        assert_eq!(children.left.depth(), children.right.depth());
        let (depth, root) = {
            let left = children.left.clone();
            let right = children.right.clone();
            let depth = left.depth() + 1;
            let root = H::hash_node(&left.root(), &right.root());
            (depth, root)
        };
        Self {
            depth,
            root,
            children: Some(children),
        }
    }
}

impl<H: Hasher> Clone for SparseTree<H> {
    fn clone(&self) -> Self {
        Self {
            depth:    self.depth,
            root:     self.root.clone(),
            children: self.children.clone(),
        }
    }
}

impl<H: Hasher> SparseTree<H> {
    fn new(left: AnyTree<H>, right: AnyTree<H>) -> Self {
        assert_eq!(left.depth(), right.depth());
        let children = Children {
            left:  Arc::new(left),
            right: Arc::new(right),
        };
        children.into()
    }

    const fn new_leaf(value: H::Hash) -> Self {
        Self {
            depth:    0,
            root:     value,
            children: None,
        }
    }

    fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
        if let Some(children) = &self.children {
            let next_index = clear_turn_at_depth(index, self.depth);
            if get_turn_at_depth(index, self.depth) == Turn::Left {
                path.push(Branch::Left(children.right.root()));
                children.left.write_proof(next_index, path);
            } else {
                path.push(Branch::Right(children.left.root()));
                children.right.write_proof(next_index, path);
            }
        }
    }

    #[must_use]
    fn update_with_mutation_condition(
        &self,
        index: usize,
        value: &H::Hash,
        is_mutation_allowed: bool,
    ) -> Self {
        let Some(children) = &self.children else {
            // no children – this is a leaf
            return Self::new_leaf(value.clone());
        };

        let next_index = clear_turn_at_depth(index, self.depth);
        let children = if get_turn_at_depth(index, self.depth) == Turn::Left {
            let left = &children.left;
            let new_left =
                left.update_with_mutation_condition(next_index, value, is_mutation_allowed);
            Children {
                left:  Arc::new(new_left),
                right: children.right.clone(),
            }
        } else {
            let right = &children.right;
            let new_right =
                right.update_with_mutation_condition(next_index, value, is_mutation_allowed);
            Children {
                left:  children.left.clone(),
                right: Arc::new(new_right),
            }
        };

        children.into()
    }

    fn root(&self) -> H::Hash {
        self.root.clone()
    }

    fn get_leaf(&self, index: usize) -> H::Hash {
        self.children.as_ref().map_or_else(
            || self.root.clone(),
            |children| {
                let next_index = clear_turn_at_depth(index, self.depth);
                if get_turn_at_depth(index, self.depth) == Turn::Left {
                    children.left.get_leaf(next_index)
                } else {
                    children.right.get_leaf(next_index)
                }
            },
        )
    }
}

#[derive(Debug)]
struct DenseTree<H: Hasher> {
    depth:      usize,
    root_index: usize,
    storage:    Arc<Mutex<Vec<H::Hash>>>,
}

impl<H: Hasher> Clone for DenseTree<H> {
    fn clone(&self) -> Self {
        Self {
            depth:      self.depth,
            root_index: self.root_index,
            storage:    self.storage.clone(),
        }
    }
}

impl<H: Hasher> DenseTree<H> {
    fn new_with_values(values: &[H::Hash], empty_leaf: &H::Hash, depth: usize) -> Self {
        let leaf_count = 1 << depth;
        let first_leaf_index = 1 << depth;
        let storage_size = 1 << (depth + 1);
        assert!(values.len() <= leaf_count);
        let mut storage = vec![empty_leaf.clone(); storage_size];
        storage[first_leaf_index..(first_leaf_index + values.len())].clone_from_slice(values);
        for i in (1..first_leaf_index).rev() {
            let left = &storage[2 * i];
            let right = &storage[2 * i + 1];
            storage[i] = H::hash_node(left, right);
        }
        Self {
            depth,
            root_index: 1,
            storage: Arc::new(Mutex::new(storage)),
        }
    }

    fn with_ref<F, R>(&self, fun: F) -> R
    where
        F: FnOnce(DenseTreeRef<H>) -> R,
    {
        let guard = self.storage.lock().expect("lock poisoned, terminating");
        let r = DenseTreeRef {
            depth:          self.depth,
            root_index:     self.root_index,
            storage:        &guard,
            locked_storage: &self.storage,
        };
        fun(r)
    }

    fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
        self.with_ref(|r| r.write_proof(index, path));
    }

    fn get_leaf(&self, index: usize) -> H::Hash {
        self.with_ref(|r| {
            let leaf_index_in_dense_tree = index + (self.root_index << self.depth);
            r.storage[leaf_index_in_dense_tree].clone()
        })
    }

    fn update_with_mutation_condition(
        &self,
        index: usize,
        value: &H::Hash,
        is_mutation_allowed: bool,
    ) -> AnyTree<H> {
        if is_mutation_allowed {
            self.update_with_mutation(index, value);
            self.clone().into()
        } else {
            self.with_ref(|r| r.update(index, value)).into()
        }
    }

    fn update_with_mutation(&self, index: usize, value: &H::Hash) {
        let mut storage = self.storage.lock().expect("lock poisoned, terminating");
        let leaf_index_in_dense_tree = index + (self.root_index << self.depth);
        storage[leaf_index_in_dense_tree] = value.clone();
        let mut current = leaf_index_in_dense_tree / 2;
        while current > 0 {
            let left = &storage[2 * current];
            let right = &storage[2 * current + 1];
            storage[current] = H::hash_node(left, right);
            current /= 2;
        }
    }

    fn root(&self) -> H::Hash {
        self.storage.lock().unwrap()[self.root_index].clone()
    }
}

struct DenseTreeRef<'a, H: Hasher> {
    depth:          usize,
    root_index:     usize,
    storage:        &'a Vec<H::Hash>,
    locked_storage: &'a Arc<Mutex<Vec<H::Hash>>>,
}

impl<H: Hasher> From<DenseTreeRef<'_, H>> for DenseTree<H> {
    fn from(value: DenseTreeRef<H>) -> Self {
        Self {
            depth:      value.depth,
            root_index: value.root_index,
            storage:    value.locked_storage.clone(),
        }
    }
}

impl<H: Hasher> From<DenseTreeRef<'_, H>> for AnyTree<H> {
    fn from(value: DenseTreeRef<H>) -> Self {
        Self::Dense(value.into())
    }
}

impl<'a, H: Hasher> DenseTreeRef<'a, H> {
    fn root(&self) -> H::Hash {
        self.storage[self.root_index].clone()
    }

    const fn left(&self) -> DenseTreeRef<H> {
        Self {
            depth:          self.depth - 1,
            root_index:     2 * self.root_index,
            storage:        self.storage,
            locked_storage: self.locked_storage,
        }
    }

    const fn right(&self) -> DenseTreeRef<H> {
        Self {
            depth:          self.depth - 1,
            root_index:     2 * self.root_index + 1,
            storage:        self.storage,
            locked_storage: self.locked_storage,
        }
    }

    fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
        if self.depth == 0 {
            return;
        }
        let next_index = clear_turn_at_depth(index, self.depth);
        if get_turn_at_depth(index, self.depth) == Turn::Left {
            path.push(Branch::Left(self.right().root()));
            self.left().write_proof(next_index, path);
        } else {
            path.push(Branch::Right(self.left().root()));
            self.right().write_proof(next_index, path);
        }
    }

    fn update(&self, index: usize, hash: &H::Hash) -> SparseTree<H> {
        if self.depth == 0 {
            return SparseTree::new_leaf(hash.clone());
        }
        let next_index = clear_turn_at_depth(index, self.depth);
        if get_turn_at_depth(index, self.depth) == Turn::Left {
            let left = self.left();
            let new_left = left.update(next_index, hash);
            let right = self.right();
            let new_root = H::hash_node(&new_left.root(), &right.root());
            SparseTree {
                children: Some(Children {
                    left:  Arc::new(new_left.into()),
                    right: Arc::new(self.right().into()),
                }),
                root:     new_root,
                depth:    self.depth,
            }
        } else {
            let right = self.right();
            let new_right = right.update(next_index, hash);
            let left = self.left();
            let new_root = H::hash_node(&left.root(), &new_right.root());
            SparseTree {
                children: Some(Children {
                    left:  Arc::new(self.left().into()),
                    right: Arc::new(new_right.into()),
                }),
                root:     new_root,
                depth:    self.depth,
            }
        }
    }
}

struct DenseMMapTree<H: Hasher> {
    depth:      usize,
    root_index: usize,
    storage:    Arc<Mutex<MmapMutWrapper<H>>>,
}

impl<H: Hasher> Clone for DenseMMapTree<H> {
    fn clone(&self) -> Self {
        Self {
            depth:      self.depth,
            root_index: self.root_index,
            storage:    self.storage.clone(),
        }
    }
}

impl<H: Hasher> DenseMMapTree<H> {
    /// Creates a new DenseMMapTree with initial values and depth
    ///
    /// # Errors
    ///
    /// - returns Err if path buf failed to be created with provided string
    /// - returns Err if mmap creation fails
    fn new_with_values(
        values: &[H::Hash],
        empty_leaf: &H::Hash,
        depth: usize,
        mmap_file_path: &str,
    ) -> Result<Self, DenseMMapError> {
        let path_buf = match PathBuf::from_str(mmap_file_path) {
            Ok(pb) => pb,
            Err(_e) => return Err(DenseMMapError::FailedToCreatePathBuf),
        };

        let leaf_count = 1 << depth;
        let first_leaf_index = 1 << depth;
        let storage_size = 1 << (depth + 1);

        assert!(values.len() <= leaf_count);

        let mut mmap = MmapMutWrapper::new_with_initial_values(path_buf, empty_leaf, storage_size)?;
        mmap[first_leaf_index..(first_leaf_index + values.len())].clone_from_slice(values);
        for i in (1..first_leaf_index).rev() {
            let left = &mmap[2 * i];
            let right = &mmap[2 * i + 1];
            mmap[i] = H::hash_node(left, right);
        }

        Ok(Self {
            depth,
            root_index: 1,
            storage: Arc::new(Mutex::new(mmap)),
        })
    }

    /// Given the file path and tree depth,
    /// it attempts to restore the memory map
    ///
    /// # Errors
    ///
    /// - returns Err if path buf creation fails
    /// - Derives errors from MmapMutWrapper
    ///
    /// # Panics
    ///
    /// - mutex lock is poisoned
    fn attempt_restore(
        empty_leaf: &H::Hash,
        depth: usize,
        mmap_file_path: &str,
    ) -> Result<Self, DenseMMapError> {
        let path_buf = match PathBuf::from_str(mmap_file_path) {
            Ok(pb) => pb,
            Err(_e) => return Err(DenseMMapError::FailedToCreatePathBuf),
        };

        let mmap = MmapMutWrapper::attempt_restore(empty_leaf, depth, path_buf)?;

        Ok(Self {
            depth,
            root_index: 1,
            storage: Arc::new(Mutex::new(mmap)),
        })
    }

    fn with_ref<F, R>(&self, fun: F) -> R
    where
        F: FnOnce(DenseTreeMMapRef<H>) -> R,
    {
        let guard = self.storage.lock().expect("lock poisoned, terminating");
        let r = DenseTreeMMapRef {
            depth:          self.depth,
            root_index:     self.root_index,
            storage:        &guard,
            locked_storage: &self.storage,
        };
        fun(r)
    }

    fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
        self.with_ref(|r| r.write_proof(index, path));
    }

    fn get_leaf(&self, index: usize) -> H::Hash {
        self.with_ref(|r| {
            let leaf_index_in_dense_tree = index + (self.root_index << self.depth);
            r.storage[leaf_index_in_dense_tree].clone()
        })
    }

    fn update_with_mutation_condition(
        &self,
        index: usize,
        value: &H::Hash,
        is_mutation_allowed: bool,
    ) -> AnyTree<H> {
        if is_mutation_allowed {
            self.update_with_mutation(index, value);
            self.clone().into()
        } else {
            self.with_ref(|r| r.update(index, value)).into()
        }
    }

    fn update_with_mutation(&self, index: usize, value: &H::Hash) {
        let mut storage = self.storage.lock().expect("lock poisoned, terminating");
        let leaf_index_in_dense_tree = index + (self.root_index << self.depth);
        storage[leaf_index_in_dense_tree] = value.clone();
        let mut current = leaf_index_in_dense_tree / 2;
        while current > 0 {
            let left = &storage[2 * current];
            let right = &storage[2 * current + 1];
            storage[current] = H::hash_node(left, right);
            current /= 2;
        }
    }

    fn root(&self) -> H::Hash {
        self.storage.lock().expect("lock poisoned")[self.root_index].clone()
    }
}

struct DenseTreeMMapRef<'a, H: Hasher> {
    depth:          usize,
    root_index:     usize,
    storage:        &'a MmapMutWrapper<H>,
    locked_storage: &'a Arc<Mutex<MmapMutWrapper<H>>>,
}

impl<'a, H: Hasher> From<DenseTreeMMapRef<'a, H>> for DenseMMapTree<H> {
    fn from(value: DenseTreeMMapRef<H>) -> Self {
        Self {
            depth:      value.depth,
            root_index: value.root_index,
            storage:    value.locked_storage.clone(),
        }
    }
}

impl<'a, H: Hasher> From<DenseTreeMMapRef<'a, H>> for AnyTree<H> {
    fn from(value: DenseTreeMMapRef<H>) -> Self {
        Self::DenseMMap(value.into())
    }
}

impl<'a, H: Hasher> DenseTreeMMapRef<'a, H> {
    fn root(&self) -> H::Hash {
        self.storage[self.root_index].clone()
    }

    const fn left(&self) -> DenseTreeMMapRef<H> {
        Self {
            depth:          self.depth - 1,
            root_index:     2 * self.root_index,
            storage:        self.storage,
            locked_storage: self.locked_storage,
        }
    }

    const fn right(&self) -> DenseTreeMMapRef<H> {
        Self {
            depth:          self.depth - 1,
            root_index:     2 * self.root_index + 1,
            storage:        self.storage,
            locked_storage: self.locked_storage,
        }
    }

    fn write_proof(&self, index: usize, path: &mut Vec<Branch<H>>) {
        if self.depth == 0 {
            return;
        }
        let next_index = clear_turn_at_depth(index, self.depth);
        if get_turn_at_depth(index, self.depth) == Turn::Left {
            path.push(Branch::Left(self.right().root()));
            self.left().write_proof(next_index, path);
        } else {
            path.push(Branch::Right(self.left().root()));
            self.right().write_proof(next_index, path);
        }
    }

    fn update(&self, index: usize, hash: &H::Hash) -> SparseTree<H> {
        if self.depth == 0 {
            return SparseTree::new_leaf(hash.clone());
        }
        let next_index = clear_turn_at_depth(index, self.depth);
        if get_turn_at_depth(index, self.depth) == Turn::Left {
            let left = self.left();
            let new_left = left.update(next_index, hash);
            let right = self.right();
            let new_root = H::hash_node(&new_left.root(), &right.root());
            SparseTree {
                children: Some(Children {
                    left:  Arc::new(new_left.into()),
                    right: Arc::new(self.right().into()),
                }),
                root:     new_root,
                depth:    self.depth,
            }
        } else {
            let right = self.right();
            let new_right = right.update(next_index, hash);
            let left = self.left();
            let new_root = H::hash_node(&left.root(), &new_right.root());
            SparseTree {
                children: Some(Children {
                    left:  Arc::new(self.left().into()),
                    right: Arc::new(new_right.into()),
                }),
                root:     new_root,
                depth:    self.depth,
            }
        }
    }
}

pub struct MmapMutWrapper<H: Hasher> {
    mmap:    MmapMut,
    phantom: std::marker::PhantomData<H>,
}

impl<H: Hasher> MmapMutWrapper<H> {
    /// Creates a new memory map backed with file with provided size
    /// and fills the entire map with initial value
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
    pub fn new_with_initial_values(
        file_path: PathBuf,
        initial_value: &H::Hash,
        storage_size: usize,
    ) -> Result<Self, DenseMMapError> {
        let empty_hash_bytes = serialize(initial_value).expect("cannot serialize initial value");
        let initial_value_size = std::mem::size_of_val(initial_value);

        let bytes: Vec<u8> =
            empty_hash_bytes.repeat(storage_size * initial_value_size / empty_hash_bytes.len());
        let file_size: u64 = storage_size as u64 * initial_value_size as u64;

        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(file_path)
        {
            Ok(file) => file,
            Err(_e) => return Err(DenseMMapError::FileCreationFailed),
        };

        file.set_len(file_size).expect("cannot set file size");
        if let Err(_) = file.write_all(&bytes) {
            return Err(DenseMMapError::FileCannotWriteBytes);
        }

        let mmap = unsafe {
            MmapOptions::new(usize::try_from(file_size).expect("file size truncated"))
                .expect("cannot create memory map")
                .with_file(file, 0)
                .map_mut()
                .expect("cannot build memory map")
        };

        Ok(Self {
            mmap,
            phantom: std::marker::PhantomData,
        })
    }

    /// Given the file path and tree depth,
    /// it attempts to restore the memory map
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
    pub fn attempt_restore(
        empty_leaf: &H::Hash,
        depth: usize,
        file_path: PathBuf,
    ) -> Result<Self, DenseMMapError> {
        let file = match OpenOptions::new().read(true).write(true).open(file_path) {
            Ok(file) => file,
            Err(_e) => return Err(DenseMMapError::FileDoesntExist),
        };

        let size_of_empty_leaf = std::mem::size_of_val(empty_leaf);
        let expected_file_size = (1 << (depth + 1)) * size_of_empty_leaf as u64;

        if expected_file_size != file.metadata().expect("cannot get file metadata").len() {
            return Err(DenseMMapError::FileSizeShouldMatchTree);
        }

        let mmap = unsafe {
            MmapOptions::new(
                usize::try_from(expected_file_size).expect("expected file size truncated"),
            )
            .expect("cannot create memory map")
            .with_file(file, 0)
            .map_mut()
            .expect("cannot build memory map")
        };

        Ok(Self {
            mmap,
            phantom: std::marker::PhantomData,
        })
    }
}

impl<H: Hasher> Deref for MmapMutWrapper<H> {
    type Target = [H::Hash];

    fn deref(&self) -> &Self::Target {
        let bytes: &[u8] = &self.mmap;
        let ptr = bytes.as_ptr().cast::<H::Hash>();
        unsafe { std::slice::from_raw_parts(ptr, bytes.len() / std::mem::size_of::<H::Hash>()) }
    }
}

impl<H: Hasher> DerefMut for MmapMutWrapper<H> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let bytes: &mut [u8] = self.mmap.as_mut_slice();
        let ptr = bytes.as_mut_ptr().cast::<H::Hash>();
        unsafe { std::slice::from_raw_parts_mut(ptr, bytes.len() / std::mem::size_of::<H::Hash>()) }
    }
}

#[derive(Error, Debug)]
pub enum DenseMMapError {
    #[error("file size should match expected tree size")]
    FileSizeShouldMatchTree,
    #[error("file doesn't exist")]
    FileDoesntExist,
    #[error("failed to create a file")]
    FileCreationFailed,
    #[error("cannot write bytes to file")]
    FileCannotWriteBytes,
    #[error("failed to create pathbuf")]
    FailedToCreatePathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_tree::{test::Keccak256, Hasher};
    use hex_literal::hex;

    struct TestHasher;

    impl Hasher for TestHasher {
        type Hash = u64;

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            left + 2 * right + 1
        }
    }

    #[test]
    fn test_updates_in_sparse() {
        let tree_1 = LazyMerkleTree::<TestHasher>::new(2, 0);
        assert_eq!(tree_1.root(), 4);
        let tree_2 = tree_1.update(0, &1);
        assert_eq!(tree_1.root(), 4);
        assert_eq!(tree_2.root(), 5);
        let tree_3 = tree_2.update(2, &2);
        assert_eq!(tree_1.root(), 4);
        assert_eq!(tree_2.root(), 5);
        assert_eq!(tree_3.root(), 9);
    }

    #[test]
    fn test_updates_in_dense() {
        let tree_1 = LazyMerkleTree::<TestHasher>::new_with_dense_prefix(2, 2, &0);
        assert_eq!(tree_1.root(), 4);
        let tree_2 = tree_1.update(0, &1);
        assert_eq!(tree_1.root(), 4);
        assert_eq!(tree_2.root(), 5);
        let tree_3 = tree_2.update(2, &2);
        assert_eq!(tree_1.root(), 4);
        assert_eq!(tree_2.root(), 5);
        assert_eq!(tree_3.root(), 9);
    }

    #[test]
    fn test_mutable_updates_in_dense() {
        let tree = LazyMerkleTree::<Keccak256>::new_with_dense_prefix(2, 2, &[0; 32]);
        let original_tree = LazyMerkleTree {
            tree:     tree.tree.clone(),
            _version: Derived,
        };
        assert_eq!(
            original_tree.root(),
            hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30")
        );
        let tree = tree.update_with_mutation(
            0,
            &hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        assert_eq!(
            original_tree.root(),
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95")
        );
        let tree = tree.update_with_mutation(
            1,
            &hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        );
        assert_eq!(
            original_tree.root(),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b")
        );
        let tree = tree.update_with_mutation(
            2,
            &hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        );
        assert_eq!(
            original_tree.root(),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c")
        );
        let _tree = tree.update_with_mutation(
            3,
            &hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        );
        assert_eq!(
            original_tree.root(),
            hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36")
        );
    }

    #[test]
    fn test_mutable_updates_in_dense_with_dense_prefix() {
        let h0 = [0; 32];
        let h1 = hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let h2 = hex!("0000000000000000000000000000000000000000000000000000000000000002");
        let h3 = hex!("0000000000000000000000000000000000000000000000000000000000000003");
        let h4 = hex!("0000000000000000000000000000000000000000000000000000000000000004");
        let tree = LazyMerkleTree::<Keccak256>::new_with_dense_prefix(2, 1, &[0; 32]);
        let original_tree = LazyMerkleTree {
            tree:     tree.tree.clone(),
            _version: Derived,
        };
        assert_eq!(
            tree.root(),
            hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30")
        );
        let t1 = tree.update_with_mutation(0, &h1);
        assert_eq!(
            t1.root(),
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95")
        );
        let t2 = t1.update_with_mutation(1, &h2);
        assert_eq!(
            t2.root(),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b")
        );
        let t3 = t2.update_with_mutation(2, &h3);
        assert_eq!(
            t3.root(),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c")
        );
        let t4 = t3.update_with_mutation(3, &h4);
        assert_eq!(
            t4.root(),
            hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36")
        );
        // first two leaves are in the dense subtree, the rest is sparse, therefore only
        // first 2 get updated inplace.
        assert_eq!(original_tree.leaves().collect::<Vec<_>>(), vec![
            h1, h2, h0, h0
        ]);
        // all leaves are updated in the properly tracked tree
        assert_eq!(t4.leaves().collect::<Vec<_>>(), vec![h1, h2, h3, h4]);
    }

    #[test]
    fn test_proof() {
        let tree = LazyMerkleTree::<Keccak256>::new_with_dense_prefix(2, 1, &[0; 32]);
        let tree = tree.update_with_mutation(
            0,
            &hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        let tree = tree.update_with_mutation(
            1,
            &hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        );
        let tree = tree.update_with_mutation(
            2,
            &hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        );
        let tree = tree.update_with_mutation(
            3,
            &hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        );

        let proof = tree.proof(2);
        assert_eq!(proof.leaf_index(), 2);
        assert!(tree.verify(
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            &proof
        ));
        assert!(!tree.verify(
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            &proof
        ));
    }

    #[test]
    fn test_giant_tree_with_initial_vals() {
        let h0 = [0; 32];
        let h1 = hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let h2 = hex!("0000000000000000000000000000000000000000000000000000000000000002");
        let h3 = hex!("0000000000000000000000000000000000000000000000000000000000000003");
        let h4 = hex!("0000000000000000000000000000000000000000000000000000000000000004");
        let updates: Vec<(usize, _)> = vec![(0, h1), (1, h2), (2, h3), (3, h4)];
        let mut from_empty =
            LazyMerkleTree::<Keccak256>::new_with_dense_prefix(63, 10, &h0).derived();
        for (ix, hash) in &updates {
            from_empty = from_empty.update(*ix, hash);
        }
        let from_initial_vals =
            LazyMerkleTree::<Keccak256>::new_with_dense_prefix_with_initial_values(63, 10, &h0, &[
                h1, h2, h3, h4,
            ])
            .derived();
        assert_eq!(from_empty.root(), from_initial_vals.root());
    }

    #[test]
    fn test_giant_trees() {
        let h0 = [0; 32];
        let h1 = hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let h2 = hex!("0000000000000000000000000000000000000000000000000000000000000002");
        let h3 = hex!("0000000000000000000000000000000000000000000000000000000000000003");
        let h4 = hex!("0000000000000000000000000000000000000000000000000000000000000004");
        let updates: Vec<(usize, _)> = vec![
            (1, h1),
            (2, h2),
            (1_000_000_000, h3),
            (1_000_000_000_000, h4),
        ];
        let mut tree = LazyMerkleTree::<Keccak256>::new_with_dense_prefix(63, 10, &h0).derived();
        for (ix, hash) in &updates {
            tree = tree.update(*ix, hash);
        }
        for (ix, hash) in &updates {
            let proof = tree.proof(*ix);
            assert_eq!(proof.root(*hash), tree.root());
        }
        let first_three_leaves = tree.leaves().take(3).collect::<Vec<_>>();
        assert_eq!(first_three_leaves, vec![h0, h1, h2]);

        let mut tree = LazyMerkleTree::<Keccak256>::new_with_dense_prefix(63, 10, &h0);
        let original_tree = tree.derived();
        for (ix, hash) in &updates {
            tree = tree.update_with_mutation(*ix, hash);
        }
        for (ix, hash) in &updates {
            let proof = tree.proof(*ix);
            assert_eq!(proof.root(*hash), tree.root());
        }
        let first_three_leaves = original_tree.leaves().take(3).collect::<Vec<_>>();
        assert_eq!(first_three_leaves, vec![h0, h1, h2]);
        let first_three_leaves = tree.leaves().take(3).collect::<Vec<_>>();
        assert_eq!(first_three_leaves, vec![h0, h1, h2]);
    }

    #[test]
    fn test_dense_mmap_tree() {
        let h0 = [0; 32];
        let h1 = hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let h2 = hex!("0000000000000000000000000000000000000000000000000000000000000002");
        let h3 = hex!("0000000000000000000000000000000000000000000000000000000000000003");
        let h4 = hex!("0000000000000000000000000000000000000000000000000000000000000004");
        let h5 = hex!("0000000000000000000000000000000000000000000000000000000000000005");
        let h6 = hex!("0000000000000000000000000000000000000000000000000000000000000006");
        let h7 = hex!("0000000000000000000000000000000000000000000000000000000000000007");
        let h8 = hex!("0000000000000000000000000000000000000000000000000000000000000008");

        let initial_values = vec![h1, h2, h3, h4, h5, h6, h7, h8];

        let tree: LazyMerkleTree<Keccak256, Canonical> =
            LazyMerkleTree::<Keccak256>::new_mmapped_with_dense_prefix_with_init_values(
                3,
                3,
                &h0,
                &initial_values,
                "./testfile",
            )
            .unwrap();
        let tree_leaves = tree.leaves().collect::<Vec<_>>();

        assert_eq!(tree_leaves, initial_values);

        let proof_h1 = tree.proof(0);
        assert!(tree.verify(h1, &proof_h1));

        let proof_h2 = tree.proof(1);
        assert!(tree.verify(h2, &proof_h2));

        // drop a tree, the mmap file should still be there
        drop(tree);

        let tree: LazyMerkleTree<Keccak256, Canonical> =
            LazyMerkleTree::<Keccak256>::attempt_dense_mmap_restore(&h0, 3, "./testfile").unwrap();

        // repeat asserts again
        let tree_leaves = tree.leaves().collect::<Vec<_>>();

        assert_eq!(tree_leaves, initial_values);

        let proof_h1 = tree.proof(0);
        assert!(tree.verify(h1, &proof_h1));

        let proof_h2 = tree.proof(1);
        assert!(tree.verify(h2, &proof_h2));

        // remove mmap file at the end
        std::fs::remove_file("./testfile").unwrap();
    }
}

#[cfg(feature = "bench")]
pub mod bench {
    use crate::{poseidon_tree::PoseidonHash, Field};

    #[allow(clippy::wildcard_imports)]
    use super::*;
    use criterion::{BenchmarkId, Criterion};

    struct TreeValues<H: Hasher> {
        depth:          usize,
        prefix_depth:   usize,
        empty_value:    H::Hash,
        initial_values: Vec<H::Hash>,
    }

    pub fn group(criterion: &mut Criterion) {
        bench_create_dense_tree(criterion);
        bench_create_dense_mmap_tree(criterion);
        bench_restore_dense_mmap_tree(criterion);
        bench_dense_tree_reads(criterion);
        bench_dense_mmap_tree_reads(criterion);
        bench_dense_tree_writes(criterion);
        bench_dense_mmap_tree_writes(criterion);
    }

    fn bench_create_dense_tree(criterion: &mut Criterion) {
        let tree_values = vec![
            create_values_for_tree(4),
            create_values_for_tree(10),
            create_values_for_tree(14),
        ];

        let mut group = criterion.benchmark_group("bench_create_dense_tree");

        for value in tree_values.iter() {
            group.bench_with_input(BenchmarkId::from_parameter(format!("create_dense_tree_depth_{}", value.depth)), value, |bencher: &mut criterion::Bencher, value| {
                bencher.iter(|| {
                    let _tree = LazyMerkleTree::<PoseidonHash, Canonical>::new_with_dense_prefix_with_initial_values(value.depth, value.prefix_depth, &value.empty_value, &value.initial_values);
                    let _root = _tree.root();
                });
            });
        }
        group.finish();
    }

    fn bench_create_dense_mmap_tree(criterion: &mut Criterion) {
        let tree_values = vec![
            create_values_for_tree(4),
            create_values_for_tree(10),
            create_values_for_tree(14),
        ];

        let mut group = criterion.benchmark_group("bench_create_dense_mmap_tree");

        for value in tree_values.iter() {
            group.bench_with_input(BenchmarkId::from_parameter(format!("create_dense_mmap_tree_depth{}", value.depth)), value, |bencher: &mut criterion::Bencher, value| {
                bencher.iter(|| {
                    let _tree = LazyMerkleTree::<PoseidonHash, Canonical>::new_mmapped_with_dense_prefix_with_init_values(value.depth, value.prefix_depth, &value.empty_value, &value.initial_values, "./testfile").unwrap();
                    let _root = _tree.root();
                });
            });
        }
        group.finish();
        // remove created mmap file
        std::fs::remove_file("./testfile").unwrap();
    }

    fn bench_restore_dense_mmap_tree(criterion: &mut Criterion) {
        let tree_values = vec![
            create_values_for_tree(4),
            create_values_for_tree(10),
            create_values_for_tree(14),
        ];

        // create 3 trees with different sizes, that are immediately dropped, but mmap
        // file should be saved
        (0..3).zip(&tree_values).for_each(|(id, value)| {
            let _tree = LazyMerkleTree::<PoseidonHash, Canonical>::new_mmapped_with_dense_prefix_with_init_values(value.depth, value.prefix_depth, &value.empty_value, &value.initial_values, &format!("./testfile{}", id)).unwrap();
            let _root = _tree.root();
        });

        let mut group = criterion.benchmark_group("bench_restore_dense_mmap_tree");

        (0..3).zip(tree_values).for_each(|(id, value)| {
            group.bench_with_input(
                BenchmarkId::from_parameter(format!(
                    "restore_dense_mmap_tree_depth_{}",
                    value.depth
                )),
                &(id, value),
                |bencher: &mut criterion::Bencher, (id, value)| {
                    bencher.iter(|| {
                        let _tree =
                            LazyMerkleTree::<PoseidonHash, Canonical>::attempt_dense_mmap_restore(
                                &value.empty_value,
                                value.depth + 1,
                                &format!("./testfile{}", id),
                            )
                            .unwrap();
                        let _root = _tree.root();
                    });
                },
            );
        });
        group.finish();
        // remove created mmap files
        std::fs::remove_file("./testfile0").unwrap();
        std::fs::remove_file("./testfile1").unwrap();
        std::fs::remove_file("./testfile2").unwrap();
    }

    #[allow(unused)]
    fn bench_dense_tree_reads(criterion: &mut Criterion) {
        let tree_value = create_values_for_tree(14);

        let tree = LazyMerkleTree::<PoseidonHash>::new_with_dense_prefix_with_initial_values(
            tree_value.depth,
            tree_value.prefix_depth,
            &tree_value.empty_value,
            &tree_value.initial_values,
        );

        criterion.bench_function("dense tree reads", |b| {
            b.iter(|| {
                // read all leaves, and compare to ones in tree value
                ((1 << (tree_value.depth - 1))..(1 << tree_value.depth)).for_each(|index| {
                    let _proof = tree.proof(index);
                })
            })
        });
    }

    #[allow(unused)]
    fn bench_dense_mmap_tree_reads(criterion: &mut Criterion) {
        let tree_value = create_values_for_tree(14);

        let tree = LazyMerkleTree::<PoseidonHash>::new_mmapped_with_dense_prefix_with_init_values(
            tree_value.depth,
            tree_value.prefix_depth,
            &tree_value.empty_value,
            &tree_value.initial_values,
            "./testfile",
        )
        .unwrap();

        criterion.bench_function("dense mmap tree reads", |b| {
            b.iter(|| {
                // read all leaves, and compare to ones in tree value
                ((1 << (tree.depth() - 1))..(1 << tree.depth())).for_each(|index| {
                    let _proof = tree.proof(index);
                })
            })
        });
        // remove mmap file
        std::fs::remove_file("./testfile");
    }

    #[allow(unused)]
    fn bench_dense_tree_writes(criterion: &mut Criterion) {
        let tree_value = create_values_for_tree(14);

        let mut tree = LazyMerkleTree::<PoseidonHash>::new_with_dense_prefix_with_initial_values(
            tree_value.depth,
            tree_value.prefix_depth,
            &tree_value.empty_value,
            &tree_value.initial_values,
        );

        let value = Field::from(123_456);

        criterion.bench_function("dense tree writes", |b| {
            let tree = tree.tree.clone();
            b.iter(|| {
                let _new_tree = tree.update_with_mutation_condition(9000, &value, true);
            });
        });
    }

    #[allow(unused)]
    fn bench_dense_mmap_tree_writes(criterion: &mut Criterion) {
        let tree_value = create_values_for_tree(14);

        let mut tree =
            LazyMerkleTree::<PoseidonHash>::new_mmapped_with_dense_prefix_with_init_values(
                tree_value.depth,
                tree_value.prefix_depth,
                &tree_value.empty_value,
                &tree_value.initial_values,
                "./testfile",
            )
            .unwrap();

        let value = Field::from(123_456);

        criterion.bench_function("dense mmap tree writes", |b| {
            let tree = tree.tree.clone();
            b.iter(|| {
                let _new_tree = tree.update_with_mutation_condition(9000, &value, true);
            });
        });
        // remove mmap file
        std::fs::remove_file("./testfile");
    }

    fn create_values_for_tree(depth: usize) -> TreeValues<PoseidonHash> {
        let prefix_depth = depth;
        let empty_value = Field::from(0);

        let initial_values: Vec<ruint::Uint<256, 4>> =
            (0..(1 << depth)).map(|value| Field::from(value)).collect();

        TreeValues {
            depth,
            prefix_depth,
            empty_value,
            initial_values,
        }
    }
}
