use hasher::Hasher;
use poseidon::Poseidon;
use trees::imt::MerkleTree;

pub type PoseidonTree = MerkleTree<Poseidon>;
// TODO: Reintroduce
// pub type LazyPoseidonTree = LazyMerkleTree<Poseidon>;
pub type Branch = trees::Branch<<Poseidon as Hasher>::Hash>;
pub type Proof = trees::Proof<Poseidon>;
