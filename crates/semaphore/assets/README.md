# Vendored proving keys

These converted Semaphore proving keys cover depths 16, 20, and 30. They are
included in the crate so every supported depth builds without downloading or
converting a proving key. Missing artifacts fail explicitly, without a network
fallback.

## Sources and integrity

- Depth 16: the existing `crates/ark-zkey/src/semaphore.16.arkzkey` test fixture.
- Depth 20: a previous `signup-sequencer` build's converted key, with matching
  hashes in two separate local build output directories.
- Depth 30: a previous `world-chain` build's converted key.

The cached artifacts were produced by the existing Semaphore build pipeline,
which downloaded from
`https://www.trusted-setup-pse.org/semaphore/{depth}/semaphore.zkey`.
These hashes record the vendored bytes; they are not independently published
ceremony attestations. Validate changes against the existing deterministic
proof vectors and end-to-end proof generation and verification.

| Depth | SHA-256 of `semaphore.arkzkey` |
| --- | --- |
| 16 | `7c9bcba20e960f66659af80e40e0b12800cbdda093e208bd32839289b7c1e07c` |
| 20 | `5147f15f9377891c00e9a81ecf87c0362f12c081ba2322cc952b395add3cd1b6` |
| 30 | `775fb904b5e3f3263f3953dc1c4202e8370d048320229f486c69d65ce6f0ce4c` |

Run compatibility checks with:

```sh
cargo test -p semaphore-rs --all-features test_single_impl
cargo test -p semaphore-rs --all-features test_proof_serialize
```
