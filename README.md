# Semaphore-rs

Rust support library for Semaphore

## Build static lib via ffi

Build e.g. for iOS simulator:

`cargo build --release --target=aarch64-apple-ios-sim`

Generate header file:

`cbindgen ./src/lib.rs -c cbindgen.toml | grep -v \#include | uniq > libsemaphore.h`