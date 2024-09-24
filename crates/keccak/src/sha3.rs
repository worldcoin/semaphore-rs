use hasher::Hasher;
use tiny_keccak::{Hasher as _, Sha3};

pub struct Sha3_256;

impl Hasher for Sha3_256 {
    type Hash = [u8; 32];

    fn hash_node(left: &Self::Hash, right: &Self::Hash) -> Self::Hash {
        let mut sha3_hasher = Sha3::v256();

        sha3_hasher.update(left);
        sha3_hasher.update(right);

        let mut out = [0u8; 32];
        sha3_hasher.finalize(&mut out);

        out
    }
}
