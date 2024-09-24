//! Implements basic binary Merkle trees

use std::fmt::Debug;
use std::iter::{once, repeat, successors};

use bytemuck::Pod;

use crate::hasher::Hasher;
use crate::proof::{Branch, Proof};

/// Merkle tree with all leaf and intermediate hashes stored
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerkleTree<H>
where
    H: Hasher,
{
    /// Depth of the tree, # of layers including leaf layer
    depth: usize,

    /// Hash value of empty subtrees of given depth, starting at leaf level
    empty: Vec<H::Hash>,

    /// Hash values of tree nodes and leaves, breadth first order
    nodes: Vec<H::Hash>,
}

/// For a given node index, return the parent node index
/// Returns None if there is no parent (root node)
const fn parent(index: usize) -> Option<usize> {
    if index <= 1 {
        return None;
    } else {
        Some(index >> 1)
    }
}

/// For a given node index, return index of the first (left) child.
const fn first_child(index: usize) -> usize {
    index << 1
}

const fn depth(index: usize) -> usize {
    // `n.next_power_of_two()` will return `n` iff `n` is a power of two.
    // The extra offset corrects this.
    (index + 2).next_power_of_two().trailing_zeros() as usize - 1
}

impl<H> MerkleTree<H>
where
    H: Hasher,
    <H as Hasher>::Hash: Clone + Copy + Pod + Eq,
{
    /// Creates a new `MerkleTree`
    /// * `depth` - The depth of the tree, including the root. This is 1 greater
    ///   than the `treeLevels` argument to the Semaphore contract.
    pub fn new(depth: usize, initial_leaf: H::Hash) -> Self {
        // Compute empty node values, leaf to root
        let empty = successors(Some(initial_leaf), |prev| Some(H::hash_node(prev, prev)))
            .take(depth)
            .collect::<Vec<_>>();

        // Compute node values
        let nodes = empty
            .iter()
            .rev()
            .enumerate()
            .flat_map(|(depth, hash)| repeat(hash).take(1 << depth))
            .cloned()
            .collect::<Vec<_>>();
        debug_assert!(nodes.len() == (1 << depth) - 1);

        Self {
            depth,
            empty,
            nodes,
        }
    }

    #[must_use]
    pub fn num_leaves(&self) -> usize {
        self.depth
            .checked_sub(1)
            .map(|n| 1 << n)
            .unwrap_or_default()
    }

    #[must_use]
    pub fn root(&self) -> H::Hash {
        self.nodes[0]
    }

    pub fn set(&mut self, leaf: usize, hash: H::Hash) {
        self.set_range(leaf, once(hash));
    }

    pub fn set_range<I: IntoIterator<Item = H::Hash>>(&mut self, start: usize, hashes: I) {
        let index = self.num_leaves() + start - 1;
        let mut count = 0;
        // TODO: Error/panic when hashes is longer than available leafs
        for (leaf, hash) in self.nodes[index..].iter_mut().zip(hashes) {
            *leaf = hash;
            count += 1;
        }
        if count != 0 {
            self.update_nodes(index, index + (count - 1));
        }
    }

    fn update_nodes(&mut self, start: usize, end: usize) {
        debug_assert_eq!(depth(start), depth(end));
        if let (Some(start), Some(end)) = (parent(start), parent(end)) {
            for parent in start..=end {
                let child = first_child(parent);
                self.nodes[parent] = H::hash_node(&self.nodes[child], &self.nodes[child + 1]);
            }
            self.update_nodes(start, end);
        }
    }

    #[must_use]
    pub fn proof(&self, leaf: usize) -> Option<Proof<H>> {
        if leaf >= self.num_leaves() {
            return None;
        }
        let mut index = self.num_leaves() + leaf - 1;
        let mut path = Vec::with_capacity(self.depth);
        while let Some(parent) = parent(index) {
            // Add proof for node at index to parent
            path.push(match index & 1 {
                1 => Branch::Left(self.nodes[index + 1]),
                0 => Branch::Right(self.nodes[index - 1]),
                _ => unreachable!(),
            });
            index = parent;
        }
        Some(Proof(path))
    }

    #[must_use]
    pub fn verify(&self, hash: H::Hash, proof: &Proof<H>) -> bool {
        proof.root(hash) == self.root()
    }

    #[must_use]
    pub fn leaves(&self) -> &[H::Hash] {
        &self.nodes[(self.num_leaves() - 1)..]
    }
}

impl<H: Hasher> Proof<H> {
    /// Compute the leaf index for this proof
    #[must_use]
    pub fn leaf_index(&self) -> usize {
        self.0.iter().rev().fold(0, |index, branch| match branch {
            Branch::Left(_) => index << 1,
            Branch::Right(_) => (index << 1) + 1,
        })
    }

    /// Compute the Merkle root given a leaf hash
    #[must_use]
    pub fn root(&self, hash: H::Hash) -> H::Hash {
        self.0.iter().fold(hash, |hash, branch| match branch {
            Branch::Left(sibling) => H::hash_node(&hash, sibling),
            Branch::Right(sibling) => H::hash_node(sibling, &hash),
        })
    }
}

impl<T: Debug> Debug for Branch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Left(arg0) => f.debug_tuple("Left").field(arg0).finish(),
            Self::Right(arg0) => f.debug_tuple("Right").field(arg0).finish(),
        }
    }
}

impl<H> Debug for Proof<H>
where
    H: Hasher,
    H::Hash: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Proof").field(&self.0).finish()
    }
}

#[cfg(test)]
pub mod test {
    use hex_literal::hex;
    use test_case::test_case;

    use super::*;
    use crate::hashes::tiny_keccak::Keccak256;

    #[test_case(0 => None)]
    #[test_case(1 => Some(0))]
    #[test_case(2 => Some(0))]
    #[test_case(3 => Some(1))]
    #[test_case(4 => Some(1))]
    #[test_case(5 => Some(2))]
    #[test_case(6 => Some(2))]
    fn parent_of(index: usize) -> Option<usize> {
        parent(index)
    }

    #[test_case(1 => 2)]
    #[test_case(2 => 4)]
    #[test_case(3 => 6)]
    fn first_child_of(index: usize) -> usize {
        first_child(index)
    }

    #[test_case(0 => 0)]
    #[test_case(1 => 1)]
    #[test_case(2 => 1)]
    #[test_case(3 => 2)]
    #[test_case(6 => 2)]
    fn depth_of(index: usize) -> usize {
        depth(index)
    }

    #[test_case(3 => hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30"))]
    fn empty(depth: usize) -> [u8; 32] {
        let tree = MerkleTree::<Keccak256>::new(depth, [0; 32]);

        tree.root()
    }
}
