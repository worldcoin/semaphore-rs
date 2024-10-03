//! Implements basic binary Merkle trees

use std::fmt::Debug;
use std::iter::{once, repeat, successors};

use bytemuck::Pod;
use derive_where::derive_where;
use hasher::Hasher;

use crate::proof::{Branch, Proof};

/// Merkle tree with all leaf and intermediate hashes stored
#[derive_where(Clone; <H as Hasher>::Hash: Clone)]
#[derive_where(PartialEq; <H as Hasher>::Hash: PartialEq)]
#[derive_where(Eq; <H as Hasher>::Hash: Eq)]
#[derive_where(Debug; <H as Hasher>::Hash: Debug)]
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
        None
    } else {
        Some(index >> 1)
    }
}

/// For a given node index, return index of the first (left) child.
const fn left_child(index: usize) -> usize {
    index << 1
}

const fn depth(index: usize) -> usize {
    // `n.next_power_of_two()` will return `n` iff `n` is a power of two.
    // The extra offset corrects this.
    if index <= 1 {
        return 0;
    }

    index.ilog2() as usize
}

impl<H> MerkleTree<H>
where
    H: Hasher,
    <H as Hasher>::Hash: Clone + Copy + Pod + Eq + Debug,
{
    /// Creates a new `MerkleTree`
    /// * `depth` - The depth of the tree, including the root. This is 1 greater
    ///   than the `treeLevels` argument to the Semaphore contract.
    pub fn new(depth: usize, initial_leaf: H::Hash) -> Self {
        // Compute empty node values, leaf to root
        let empty = successors(Some(initial_leaf), |prev| Some(H::hash_node(prev, prev)))
            .take(depth + 1)
            .collect::<Vec<_>>();

        // Compute node values
        let first_node = std::iter::once(initial_leaf);
        let nodes = empty
            .iter()
            .rev()
            .enumerate()
            .flat_map(|(depth, hash)| repeat(hash).take(1 << depth))
            .cloned();

        let nodes = first_node.chain(nodes).collect();

        Self {
            depth,
            empty,
            nodes,
        }
    }

    #[must_use]
    pub fn num_leaves(&self) -> usize {
        1 << self.depth
    }

    #[must_use]
    pub fn root(&self) -> H::Hash {
        self.nodes[1]
    }

    pub fn set(&mut self, leaf: usize, hash: H::Hash) {
        self.set_range(leaf, once(hash));
    }

    pub fn set_range<I: IntoIterator<Item = H::Hash>>(&mut self, start: usize, hashes: I) {
        let index = self.num_leaves() + start;

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
                let child = left_child(parent);
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
        let mut index = self.num_leaves() + leaf;
        let mut path = Vec::with_capacity(self.depth);
        while let Some(parent) = parent(index) {
            // Add proof for node at index to parent
            path.push(match index & 1 {
                1 => Branch::Right(self.nodes[index - 1]),
                0 => Branch::Left(self.nodes[index + 1]),
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

#[cfg(test)]
pub mod test {
    use hex_literal::hex;
    use keccak::keccak::Keccak256;
    use poseidon::Poseidon;
    use ruint::aliases::U256;
    use test_case::test_case;

    use super::*;

    #[test_case(0 => None)]
    #[test_case(1 => None)]
    #[test_case(2 => Some(1))]
    #[test_case(3 => Some(1))]
    #[test_case(4 => Some(2))]
    #[test_case(5 => Some(2))]
    #[test_case(6 => Some(3))]
    #[test_case(27 => Some(13))]
    fn parent_of(index: usize) -> Option<usize> {
        parent(index)
    }

    #[test_case(0 => 0 ; "Nonsense case")]
    #[test_case(1 => 2)]
    #[test_case(2 => 4)]
    #[test_case(3 => 6)]
    fn left_child_of(index: usize) -> usize {
        left_child(index)
    }

    #[test_case(0 => 0)]
    #[test_case(1 => 0)]
    #[test_case(2 => 1)]
    #[test_case(3 => 1)]
    #[test_case(6 => 2)]
    fn depth_of(index: usize) -> usize {
        depth(index)
    }

    #[test_case(2 => hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30"))]
    fn empty_keccak(depth: usize) -> [u8; 32] {
        let tree = MerkleTree::<Keccak256>::new(depth, [0; 32]);

        tree.root()
    }

    #[test]
    fn simple_poseidon() {
        let mut tree = MerkleTree::<Poseidon>::new(10, U256::ZERO);

        let expected_root = ruint::uint!(
            12413880268183407374852357075976609371175688755676981206018884971008854919922_U256
        );
        assert_eq!(tree.root(), expected_root);

        tree.set(0, ruint::uint!(1_U256));

        let expected_root = ruint::uint!(
            467068234150758165281816522946040748310650451788100792957402532717155514893_U256
        );
        assert_eq!(tree.root(), expected_root);
    }
}
