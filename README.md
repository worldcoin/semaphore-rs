# README

## Native ios library


### Setup build environnement

See the [instructions from Mozilla](https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-06-rust-on-ios.html).

We will focus only on `aarch64` and skip the multi-arch. This means an iPhone 5S or later is required.

```shell
xcode-select --install
rustup target add aarch64-apple-ios
xcrun --show-sdk-path --sdk iphoneos
```

If you get the error `xcrun: error: SDK "iphoneos" cannot be located`, run `sudo xcode-select --switch /Applications/Xcode.app`. See [here](https://www.ryadel.com/en/xcode-sdk-iphoneos-cannot-be-located-mac-osx-error-fix/).

### Build library

```shell
cargo build --release --lib --target aarch64-apple-ios
```

```shell
ls -lah ./target/aarch64-apple-ios/release
```

### Check bloatiness

We can not check the static library directly. Instead we will compile a minimal executable that uses it and check that.

```shell
cargo bloat --release --target aarch64-apple-ios --crates -n 30
```
