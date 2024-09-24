/// Hash types, values and algorithms for a Merkle tree
pub trait Hasher {
    /// Type of the leaf and node hashes
    type Hash;

    /// Compute the hash of an intermediate node
    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash;
}
