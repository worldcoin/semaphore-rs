# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.3](https://github.com/worldcoin/semaphore-rs/compare/semaphore-rs-v0.5.2...semaphore-rs-v0.5.3) - 2026-03-20

### Other

- Optimize auth proofs and restore depth test macros ([#137](https://github.com/worldcoin/semaphore-rs/pull/137))

## [0.5.2](https://github.com/worldcoin/semaphore-rs/compare/semaphore-rs-v0.5.1...semaphore-rs-v0.5.2) - 2026-03-20

### Other

- update Cargo.toml dependencies

## [0.5.1](https://github.com/worldcoin/semaphore-rs/compare/semaphore-rs-v0.5.0...semaphore-rs-v0.5.1) - 2026-03-16

### Added

- gate mmap-rs and lazy trees for WASM compatibility ([#131](https://github.com/worldcoin/semaphore-rs/pull/131))
- cascade improvements ([#130](https://github.com/worldcoin/semaphore-rs/pull/130))
- check for pushing past tree depth
- check for empty range

### Other

- satisfy clippy
