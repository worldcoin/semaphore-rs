use hasher::Hasher;
use ruint::aliases::U256;

pub mod constants;
pub mod poseidon;

pub struct Poseidon;

impl Hasher for Poseidon {
    type Hash = U256;

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        poseidon::hash2(*left, *right)
    }
}
