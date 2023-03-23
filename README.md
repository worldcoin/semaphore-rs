# 🦀 semaphore-rs

Rust support library for using [semaphore](https://github.com/appliedzkp/semaphore). It's mostly a Rust rewrite of [zk-kit](https://github.com/appliedzkp/zk-kit), but just focuses on semaphore (for now) and still covers a much smaller scope. It's using [ark-circom](https://github.com/gakonst/ark-circom) under the hood for generating the groth16 proofs.

## Usage

Add this line to your `cargo.toml`:

```toml
semaphore = { git = "https://github.com/worldcoin/semaphore-rs" }
```

## Building semaphore circuits

1. Check out submodule (if not done before already): `git submodule update --init --recursive`
1. Install semaphore dependencies `cd semaphore && npm install`
1. Compile circuits `npm exec ts-node ./scripts/compile-circuits.ts`
1. You'll find the `zkey` and `wasm` file in `semaphore/build/snark`

## Example

Example as in `src/lib.rs`, run with `cargo test`.

```rust
use semaphore::{hash_to_field, Field, identity::Identity, poseidon_tree::LazyPoseidonTree,
    protocol::*, SUPPORTED_DEPTH };
use num_bigint::BigInt;

// generate identity
let id = Identity::from_secret(b"secret", None);

// generate merkle tree
let leaf = Field::from(0);
let mut tree = LazyPoseidonTree::new(SUPPORTED_DEPTH, leaf).derived();
tree = tree.update(0, &id.commitment());

let merkle_proof = tree.proof(0);
let root = tree.root();

// change signal and external_nullifier here
let signal_hash = hash_to_field(b"xxx");
let external_nullifier_hash = hash_to_field(b"appId");

let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

let proof = generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();
let success = verify_proof(root, nullifier_hash, signal_hash, external_nullifier_hash, &proof).unwrap();

assert!(success);
```
