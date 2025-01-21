use semaphore_rs_hasher::Hasher;
use tiny_keccak::{Hasher as _, Keccak};
pub struct Keccak256;

impl Hasher for Keccak256 {
    type Hash = [u8; 32];

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let mut keccak = Keccak::v256();
        let mut output = [0; 32];

        keccak.update(left);
        keccak.update(right);
        keccak.finalize(&mut output);

        output
    }
}
