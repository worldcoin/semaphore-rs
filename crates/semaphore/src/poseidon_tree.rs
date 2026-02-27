use semaphore_rs_hasher::Hasher;
use semaphore_rs_poseidon::Poseidon;
use semaphore_rs_trees::imt::MerkleTree;
#[cfg(not(target_arch = "wasm32"))]
use semaphore_rs_trees::lazy::LazyMerkleTree;

pub type PoseidonTree = MerkleTree<Poseidon>;
#[cfg(not(target_arch = "wasm32"))]
pub type LazyPoseidonTree = LazyMerkleTree<Poseidon>;
pub type Branch = semaphore_rs_trees::Branch<<Poseidon as Hasher>::Hash>;
pub type Proof = semaphore_rs_trees::InclusionProof<Poseidon>;
