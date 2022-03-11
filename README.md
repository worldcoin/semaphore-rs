# 🦀 semaphore-rs 

Rust support library for using [semaphore](https://github.com/appliedzkp/semaphore). It's mostly a Rust rewrite of [zk-kit](https://github.com/appliedzkp/zk-kit), but just focuses on semaphore (for now) and still covers a much smaller scope. It's using [ark-circom](https://github.com/gakonst/ark-circom) under the hood for generating the groth16 proofs.

## Usage

Add this line to your `cargo.toml`:
```
semaphore = { git = "https://github.com/worldcoin/semaphore-rs" }
```

## Building semaphore circuits

1. Check out submodule (if not done before already): `git submodule update --init --recursive`
1. Install semaphore dependencies `cd semaphore && npm install`
1. Compile circuits `ts-node ./scripts/compile-circuits.ts`
1. You'll find the `zkey` and `wasm` file in `semaphore/build/snark`

## Example

Example as in `src/lib.rs`, run with `cargo test`.

```rust
use semaphore::{identity::Identity, hash::Hash, poseidon_tree::PoseidonTree,
    protocol::* };
use num_bigint::BigInt;

// generate identity
let id = Identity::new(b"secret");

// generate merkle tree
const LEAF: Hash = Hash::from_bytes_be([0u8; 32]);

let mut tree = PoseidonTree::new(21, LEAF);
let (_, leaf) = id.commitment().to_bytes_be();
tree.set(0, leaf.into());

let merkle_proof = tree.proof(0).expect("proof should exist");
let root = tree.root();

// change signal and external_nullifier here
let signal = b"xxx";
let external_nullifier = b"appId";

let external_nullifier_hash = hash_external_nullifier(external_nullifier);
let nullifier_hash = generate_nullifier_hash(&id, &external_nullifier_hash);

let config = SnarkFileConfig {
    zkey: "./semaphore/build/snark/semaphore_final.zkey".to_string(),
    wasm: "./semaphore/build/snark/semaphore.wasm".to_string(),
};

let proof = generate_proof(&config, &id, &merkle_proof, &external_nullifier_hash, signal).unwrap();
let success = verify_proof(&config, &root.into(), &nullifier_hash, signal, &external_nullifier_hash, &proof).unwrap();

assert!(success);
```
