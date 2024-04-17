use self::incremental_index_calculus::{children, leaf_to_node};
use crate::generic_storage::GenericStorage;
use crate::incremental_merkle_tree::incremental_index_calculus::{parent, parent_and_sibling};
use crate::merkle_tree::{Branch, Hasher};

mod incremental_index_calculus;

pub struct IncrementalMerkleTree<S, H>
where
    H: Hasher,
{
    depth:         usize,
    root:          H::Hash,
    empty_value:   H::Hash,
    sparse_column: Vec<H::Hash>,
    storage:       S,
}

impl<S, H> IncrementalMerkleTree<S, H>
where
    H: Hasher,
    S: GenericStorage<H::Hash>,
{
    pub fn new(storage: S, depth: usize, empty_value: H::Hash) -> Self {
        let sparse_column = sparse_column::<H>(depth, &empty_value);
        let initial_root = sparse_column[depth - 1].clone();

        let mut tree = IncrementalMerkleTree {
            storage,
            depth,
            sparse_column,
            root: initial_root,
            empty_value,
        };

        tree.resize_storage(2);
        tree.set_num_leaves(0);
        tree.storage[1] = empty_value;
        tree.recompute_root();

        tree
    }

    pub fn root(&self) -> H::Hash {
        self.root
    }

    pub fn push(&mut self, leaf: H::Hash) {
        self.extend(&[leaf])
    }

    pub fn extend(&mut self, leaves: &[H::Hash]) {
        let num_leaves = self.num_leaves();
        let first_new_leaf_idx = leaf_to_node(num_leaves);
        let last_new_leaf_idx = leaf_to_node(num_leaves + leaves.len() - 1);

        if self.storage.len() < last_new_leaf_idx {
            let num_nodes = last_new_leaf_idx.next_power_of_two();
            self.resize_storage(num_nodes);
        }

        for (i, leaf) in leaves.iter().enumerate() {
            let leaf_idx = leaf_to_node(num_leaves + i);
            self.storage[leaf_idx] = leaf.clone();
        }

        self.recalculate_storage(first_new_leaf_idx);
        self.set_num_leaves(num_leaves + leaves.len());
        self.recompute_root();
    }

    /// Recalculates the storage intermediate node values from a given leaf node
    /// index
    ///
    /// Performs the calculation up the tree but also recalculates every right
    /// branch of tree recursively this way if a number of new leaves were
    /// added at once we
    fn recalculate_storage(&mut self, mut current: usize) {
        // We must propagate the new leaf up the tree while
        // also recalculating every right we encounter
        // as it might have just been initialized with empty values
        loop {
            let (parent, sibling) = parent_and_sibling(current);

            if parent >= self.storage.len() {
                break;
            }

            if let Branch::Right(sibling) = sibling {
                self.recompute_storage_subtree(sibling);
            }

            self.storage[parent] =
                H::hash_node(&self.storage[current], &self.storage[sibling.into_inner()]);

            current = parent;
        }
    }

    fn recompute_storage_subtree(&mut self, idx: usize) {
        match children(idx) {
            Some((left, right)) => {
                self.recompute_storage_subtree(left);
                self.recompute_storage_subtree(right);

                self.storage[idx] = H::hash_node(&self.storage[left], &self.storage[right]);
            }
            None => {}
        }
    }

    fn num_leaves(&self) -> usize {
        bytemuck::cast_slice(&self.storage[0..1])[0]
    }

    fn set_num_leaves(&mut self, num_leaves: usize) {
        bytemuck::cast_slice_mut(&mut self.storage[0..1])[0] = num_leaves;
    }

    fn recompute_root(&mut self) {
        let (mut hash, storage_root_height) = if self.num_leaves() == 0 {
            (self.empty_value.clone(), 0)
        } else {
            let storage_root_idx = self.storage.len().next_power_of_two() >> 1;
            let storage_root = self.storage[storage_root_idx];
            let storage_root_height = self.storage.len().ilog2() as usize;

            (storage_root, storage_root_height - 1)
        };

        for h in storage_root_height..self.depth {
            let right = self.sparse_column[h].clone();

            hash = H::hash_node(&hash, &right);
        }

        self.root = hash;
    }

    /// Resize storage to fit a given number of nodes
    ///
    /// does not recompute the intermediate node values
    fn resize_storage(&mut self, new_len: usize) {
        let current_len = self.storage.len();

        self.storage
            .extend(std::iter::repeat(self.empty_value.clone()).take(new_len - current_len));
    }
}

fn sparse_column<H>(depth: usize, empty_value: &H::Hash) -> Vec<H::Hash>
where
    H: Hasher,
{
    let mut column = Vec::with_capacity(depth);

    column.push(empty_value.clone());

    for d in 1..depth {
        let prev = column[d - 1].clone();
        column.push(H::hash_node(&prev, &prev));
    }

    column
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TestHasher;
    impl Hasher for TestHasher {
        type Hash = usize;

        fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
            left + right
        }
    }

    #[test]
    fn root_of_empty() {
        let storage: Vec<<TestHasher as Hasher>::Hash> = Vec::new();
        let empty_value = 1;
        let tree: IncrementalMerkleTree<_, TestHasher> =
            IncrementalMerkleTree::new(storage, 2, empty_value);

        assert_eq!(tree.root(), 4);
    }

    #[test]
    fn incremental_push() {
        let storage: Vec<<TestHasher as Hasher>::Hash> = Vec::new();
        let empty_value = 1;
        let mut tree: IncrementalMerkleTree<_, TestHasher> =
            IncrementalMerkleTree::new(storage, 2, empty_value);

        tree.push(2);
        //     5
        //  3    2
        // 2 1  1 1
        assert_eq!(tree.root(), 5);

        tree.push(3);
        //     7
        //  5    2
        // 2 3  1 1
        println!("tree.storage = {:?}", tree.storage);
        assert_eq!(tree.root(), 7);

        tree.push(10);
        //     16
        //  5     11
        // 2 3  10  1
        println!("tree.storage = {:?}", tree.storage);
        assert_eq!(tree.root(), 16);

        tree.push(123);
        println!("tree.storage = {:?}", tree.storage);
        //     138
        //  5     133
        // 2 3  10  123
        assert_eq!(tree.root(), 138);
    }

    #[test]
    fn incremental_push_depth_3() {
        let storage: Vec<<TestHasher as Hasher>::Hash> = Vec::new();
        let empty_value = 1;
        let mut tree: IncrementalMerkleTree<_, TestHasher> =
            IncrementalMerkleTree::new(storage, 3, empty_value);

        //          8
        //     4         4
        //  2    2    2    2
        // 1 1  1 1  1 1  1 1
        assert_eq!(tree.root(), 8);

        tree.push(2);
        //          9
        //     5         4
        //  3    2    2    2
        // 2 1  1 1  1 1  1 1
        assert_eq!(tree.root(), 9);

        tree.push(3);
        //          11
        //     7         4
        //  5    2    2    2
        // 2 3  1 1  1 1  1 1
        assert_eq!(tree.root(), 11);

        tree.push(10);
        //          20
        //     16          4
        //  5     11    2    2
        // 2 3  10  1  1 1  1 1
        println!("tree.storage = {:?}", tree.storage);
        assert_eq!(tree.root(), 20);

        tree.push(123);
        println!("tree.storage = {:?}", tree.storage);
        //            142
        //     138            4
        //  5     133       2    2
        // 2 3  10  123   1 1  1 1
        assert_eq!(tree.root(), 142);

        tree.push(2);
        //            143
        //     138            5
        //  5     133       3    2
        // 2 3  10  123   2 1  1 1
        assert_eq!(tree.root(), 143);
    }

    #[test]
    fn incremental_extend_depth_3() {
        let storage: Vec<<TestHasher as Hasher>::Hash> = Vec::new();
        let empty_value = 1;
        let mut tree: IncrementalMerkleTree<_, TestHasher> =
            IncrementalMerkleTree::new(storage, 3, empty_value);

        //          8
        //     4         4
        //  2    2     2    2
        // 1 1  1 1   1 1  1 1
        assert_eq!(tree.root(), 8);
        tree.extend(&[2, 3, 10, 123, 2]);

        println!("tree.storage = {:?}", tree.storage);
        //            143
        //     138            5
        //  5     133       3    2
        // 2 3  10  123   2 1  1 1
        assert_eq!(tree.root(), 143);
    }
}
