use semaphore::{cascading_merkle_tree::CascadingMerkleTree, merkle_tree::Hasher};

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestHasher;
impl Hasher for TestHasher {
    type Hash = usize;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        left + right
    }
}

#[test]
fn test_abort() {
    let tree = CascadingMerkleTree::<TestHasher>::new_with_leaves((), 4, &4, &[]);
}
