# deoxysii-rust - Deoxys-II-256-128 for Rust

[![CircleCI](https://circleci.com/gh/oasislabs/deoxysii-rust.svg?style=svg&circle-token=7b28eb2bede060d972c153006a3023224eabdeca)](https://circleci.com/gh/oasislabs/deoxysii-rust)

This crate provides a Rust implementation of [Deoxys-II-256-128 v1.43][0].

The implementation uses Intel SIMD intrinsics (SSSE3 and AES-NI) for
speed and will therefore only run on relatively modern x86-64 processors.

The nightly version of Rust is required to build this crate.

To build everything, run tests and benchmarks, simply run `make`.

If you have the `RUSTFLAGS` environment variable set, it will override Rust
flags set in the repository's `.cargo/config`, so make sure you also add
`-C target-feature=+aes,+ssse3` to your custom flags or the code will fail
to build.

[0]: https://sites.google.com/view/deoxyscipher
