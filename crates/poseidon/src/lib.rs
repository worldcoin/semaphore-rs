use ruint::aliases::U256;
use semaphore_rs_hasher::Hasher;

pub mod constants;
pub mod poseidon;

pub struct Poseidon;

impl Hasher for Poseidon {
    type Hash = U256;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        poseidon::hash2(*left, *right)
    }
}
