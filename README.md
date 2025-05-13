# Rust Bindings for Firedancer's Ed25519 Cryptography

## Usage
[Sigverify example](./examples/sigverify.rs)
```bash
cargo run --example sigverify
```

## Performance
Approximately 2x faster than solana's ed25519-dalek on an AMD Ryzen 9950X, see [benches](./benches/bench_sigverify.rs)

```bash
     Running benches/bench_sigverify.rs (target/release/deps/bench_sigverify-e01361226af04f4a)
solana_sigverify        time:   [28.992 µs 29.024 µs 29.057 µs]
Found 6 outliers among 100 measurements (6.00%)
  2 (2.00%) high mild
  4 (4.00%) high severe

fd_sigverify            time:   [13.646 µs 13.662 µs 13.681 µs]
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe

```

## Directory Structure

The `ballet` C library source code is expected to be placed within the `vendor/` directory at the root of this Rust project:

Files taken from:
https://github.com/firedancer-io/firedancer/commit/91c4a47971fc26c3e01025a1a9972d6320a2961a

Directories:
- `ballet`: Copied `ed25519`, `fiat-crypto`, `hex`, and `sha512` verbatim from FD. Only modified `fd_ballet.h` to remove unnecessary imports
- `util`: Copied verbatim from FD

## Using the Bindings

Once built, you can use the cryptographic functions from your Rust code. The `src/lib.rs` file provides an example of safe Rust wrappers around the unsafe FFI calls.

Here's a conceptual example of how you might use the `fd_ed25519_verify` function: