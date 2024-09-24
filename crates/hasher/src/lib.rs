use bytemuck::Pod;

/// Hash types, values and algorithms for a Merkle tree
pub trait Hasher {
    /// Type of the leaf and node hashes
    type Hash;

    /// Compute the hash of an intermediate node
    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash;
}

/// A marker trait that indicates some useful properties of a hash type
///
/// It's not strictly necessary, but for many implementations it's a useful set of constraints
pub trait Hash: Pod + Eq + Send + Sync {}

impl<T> Hash for T where T: Pod + Eq + Send + Sync {}
