//! Proves and verifies on the current target. CI runs it on `wasm32-wasip1` under wasmtime,
//! because `cargo check` alone cannot catch arkworks panicking at runtime without threads.

use semaphore_rs::{
    hash_to_field,
    identity::Identity,
    protocol::{
        authentication::{generate_proof, verify_proof},
        generate_nullifier_hash,
    },
};

const DEPTH: usize = 16;

fn main() {
    let mut secret = *b"semaphore-rs-wasm-smoke-secret!!";
    let identity = Identity::from_secret(&mut secret, None);
    let scope = hash_to_field(b"wasm-smoke-scope");
    let challenge = hash_to_field(b"2026-01-01T00:00:00Z");

    let proof = generate_proof(DEPTH, &identity, scope, challenge).expect("generate proof");
    let nullifier = generate_nullifier_hash(&identity, scope);

    let valid = verify_proof(
        DEPTH,
        identity.commitment(),
        nullifier,
        challenge,
        scope,
        &proof,
    )
    .expect("verify proof");
    assert!(valid, "a fresh proof must verify");

    let other_challenge = hash_to_field(b"2026-01-01T00:00:01Z");
    let replayed = verify_proof(
        DEPTH,
        identity.commitment(),
        nullifier,
        other_challenge,
        scope,
        &proof,
    )
    .unwrap_or(false);
    assert!(!replayed, "a proof must not verify for another challenge");

    println!("ok: depth-{DEPTH} authentication proof generated and verified");
}
