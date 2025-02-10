#!/usr/bin/env bash

set -e

cargo publish -p semaphore-rs-utils
cargo publish -p semaphore-rs-ark-circom
cargo publish -p semaphore-rs-proof
cargo publish -p semaphore-rs-ark-zkey
cargo publish -p semaphore-rs-hasher
cargo publish -p semaphore-rs-poseidon
cargo publish -p semaphore-rs-keccak
cargo publish -p semaphore-rs-storage
cargo publish -p semaphore-rs-trees
cargo publish -p semaphore-rs-depth-config
cargo publish -p semaphore-rs-depth-macros
cargo publish -p semaphore-rs-witness
cargo publish -p semaphore-rs

