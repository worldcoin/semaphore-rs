#![feature("incremental_tree")]

use crate::merkle_tree::{Hasher, Proof};
use std::{
    borrow::Borrow,
    iter::{once, repeat, successors},
    ops::Deref,
    sync::{Arc, Mutex},
};

pub struct IncrementalMerkleTree<H: Hasher>(AnyTree<H>);

impl<H: Hasher> IncrementalMerkleTree<H> {
    pub fn new(depth: usize, empty_value: H::Hash) -> Self {
        AnyTree::new(depth, empty_value).into()
    }

    pub fn new_with_dense_prefix(depth: usize, prefix_depth: usize, empty_value: H::Hash) -> Self {
        AnyTree::new_with_dense_prefix(depth, prefix_depth, empty_value).into()
    }

    pub fn depth(&self) -> usize {
        self.0.depth()
    }

    pub fn root(&self) -> H::Hash {
        self.0.root()
    }

    pub fn update(&self, index: usize, value: &H::Hash) -> Self {
        self.0
            .update_with_destruction_condition(index, value, false)
            .into()
    }

    pub fn proof(&self, index: usize) -> Proof<H> {
        self.0.proof(index)
    }

    #[must_use]
    pub fn update_destructively(&self, index: usize, value: &H::Hash) -> Self {
        self.0
            .update_with_destruction_condition(index, value, true)
            .into()
    }

    // pub fn generate_proof(&self, index: usize, value: &H::Hash) -> Vec<H::Hash> {
    //     self.0.generate_proof(index, value)
    // }
    //
    // pub fn verify_proof(&self, index: usize, value: &H::Hash, proof: &[H::Hash])
    // -> bool {     self.0.verify_proof(index, value, proof)
    // }
}

impl<H: Hasher> From<AnyTree<H>> for IncrementalMerkleTree<H> {
    fn from(tree: AnyTree<H>) -> Self {
        Self(tree)
    }
}

enum AnyTree<H: Hasher> {
    Empty(EmptyTree<H>),
    Sparse(SparseTree<H>),
    Dense(DenseTree<H>),
}

impl<H: Hasher> AnyTree<H> {
    fn new(depth: usize, empty_value: H::Hash) -> Self {
        Self::Empty(EmptyTree::new(depth, empty_value))
    }

    fn new_with_dense_prefix(depth: usize, prefix_depth: usize, empty_value: H::Hash) -> Self {
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

    fn depth(&self) -> usize {
        match self {
            Self::Empty(tree) => tree.depth,
            Self::Sparse(tree) => tree.depth,
            Self::Dense(tree) => tree.depth,
        }
    }

    fn root(&self) -> H::Hash {
        match self {
            Self::Empty(tree) => tree.root(),
            Self::Sparse(tree) => tree.root(),
            Self::Dense(tree) => tree.root(),
        }
    }

    fn proof(&self, index: usize) -> Proof<H> {
        assert!(index < (1 << self.0.depth()));
        let mut path = Vec::with_capacity(self.depth());
        match self {
            Self::Empty(tree) => tree.write_proof(index, &mut path),
            Self::Sparse(tree) => tree.write_proof(index, &mut path),
            Self::Dense(tree) => tree.write_proof(index, &mut path),
        }
        
    }

    fn update_with_destruction_condition(
        &self,
        index: usize,
        value: &H::Hash,
        destructive: bool,
    ) -> Self {
        match self {
            Self::Empty(tree) => tree
                .update_with_destruction_condition(index, value, destructive)
                .into(),
            Self::Sparse(tree) => tree
                .update_with_destruction_condition(index, value, destructive)
                .into(),
            Self::Dense(tree) => tree
                .update_with_destruction_condition(index, value, destructive)
                .into(),
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

    #[must_use]
    fn update_with_destruction_condition(
        &self,
        index: usize,
        value: &H::Hash,
        destructive: bool,
    ) -> SparseTree<H> {
        self.alloc_sparse()
            .update_with_destruction_condition(index, value, destructive)
    }

    #[must_use]
    fn alloc_sparse(&self) -> SparseTree<H> {
        if self.depth == 0 {
            SparseTree::new_leaf(self.root())
        } else {
            let next_child: Self = EmptyTree {
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
}

struct Children<H: Hasher> {
    left:  Arc<AnyTree<H>>,
    right: Arc<AnyTree<H>>,
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

const fn log2(x: usize) -> usize {
    usize::BITS as usize - x.leading_zeros() as usize - 1
}

fn get_turn_at_depth(index: usize, depth: usize) -> Turn {
    if index & (1 << (depth - 1)) == 0 {
        Turn::Left
    } else {
        Turn::Right
    }
}

fn clear_turn_at_depth(index: usize, depth: usize) -> usize {
    index & !(1 << (depth - 1))
}

impl<H: Hasher> From<Children<H>> for SparseTree<H> {
    fn from(children: Children<H>) -> Self {
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

impl<H: Hasher> SparseTree<H> {
    fn new(left: AnyTree<H>, right: AnyTree<H>) -> Self {
        assert_eq!(left.depth(), right.depth());
        let children = Children {
            left:  Arc::new(left),
            right: Arc::new(right),
        };
        children.into()
    }

    fn new_leaf(value: H::Hash) -> Self {
        Self {
            depth:    0,
            root:     value,
            children: None,
        }
    }

    #[must_use]
    fn update_with_destruction_condition(
        &self,
        index: usize,
        value: &H::Hash,
        destructive: bool,
    ) -> Self {
        let Some(children) = &self.children else {
            // no children – this is a leaf
            return Self::new_leaf(value.clone());
        };

        let next_index = clear_turn_at_depth(index, self.depth);
        let children = if get_turn_at_depth(index, self.depth) == Turn::Left {
            let left = &children.left;
            let new_left = left.update_with_destruction_condition(next_index, value, destructive);
            Children {
                left:  Arc::new(new_left),
                right: children.right.clone(),
            }
        } else {
            let right = &children.right;
            let new_right = right.update_with_destruction_condition(next_index, value, destructive);
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

    fn update_with_destruction_condition(
        &self,
        index: usize,
        value: &H::Hash,
        destructive: bool,
    ) -> AnyTree<H> {
        if destructive {
            self.update_destructively(index, value);
            self.clone().into()
        } else {
            self.with_ref(|r| {
                let x = r.update(index, value);
                x
            })
            .into()
        }
    }

    fn update_destructively(&self, index: usize, value: &H::Hash) {
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

    fn left(&self) -> DenseTree<H> {
        Self {
            depth:      self.depth - 1,
            root_index: 2 * self.root_index,
            storage:    self.storage.clone(),
        }
    }

    fn right(&self) -> DenseTree<H> {
        Self {
            depth:      self.depth - 1,
            root_index: 2 * self.root_index,
            storage:    self.storage.clone(),
        }
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

    fn left(&self) -> DenseTreeRef<'a, H> {
        Self {
            depth:          self.depth - 1,
            root_index:     2 * self.root_index,
            storage:        self.storage,
            locked_storage: self.locked_storage,
        }
    }

    fn right(&self) -> DenseTreeRef<'a, H> {
        Self {
            depth:          self.depth - 1,
            root_index:     2 * self.root_index + 1,
            storage:        self.storage,
            locked_storage: self.locked_storage,
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
        let tree_1 = IncrementalMerkleTree::<TestHasher>::new(2, 0);
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
        let tree_1 = IncrementalMerkleTree::<TestHasher>::new_with_dense_prefix(2, 2, 0);
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
        let tree = IncrementalMerkleTree::<Keccak256>::new_with_dense_prefix(2, 2, [0; 32]);
        assert_eq!(
            tree.root(),
            hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30")
        );
        let _ = tree.update_destructively(
            0,
            &hex!("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        assert_eq!(
            tree.root(),
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95")
        );
        let _ = tree.update_destructively(
            1,
            &hex!("0000000000000000000000000000000000000000000000000000000000000002"),
        );
        assert_eq!(
            tree.root(),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b")
        );
        let _ = tree.update_destructively(
            2,
            &hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        );
        assert_eq!(
            tree.root(),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c")
        );
        let _ = tree.update_destructively(
            3,
            &hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        );
        assert_eq!(
            tree.root(),
            hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36")
        );
    }
}
