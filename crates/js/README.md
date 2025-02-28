# WASM bindings for semaphore-rs related functionality

This crate exposes semaphore-rs functionality to WASM. Currently it only exposes proof compression.

## Building & publishing

wasm-pack doesn't allow us to compile to a single target for node and browser usage. Instead we'll publish a package for each target.

The `build_and_publish.sh` script handles all of that.

To build and publish a new version simply run `./build_and_publish.sh`. Note that the package will likely fail to publish if using your own npm account.

To only check the build output run `DRY_RUN=1 ./build_and_publish.sh`.

## Example

Refer to `example/index.mjs` or `example/index.ts` for usage
