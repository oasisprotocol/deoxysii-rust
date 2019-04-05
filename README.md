# deoxysii-rust - Deoxys-II-256-128 for Rust

This crate provides a Rust implementation of [Deoxys-II-256-128 v1.41][0].

The implementation uses Intel SIMD intrinsics (SSSE3 and AES-NI) for
speed and will therefore only run on x86-64.

The nightly version of Rust is required to build this crate.

To build everything, run tests and benchmarks, simply run `make`.

[0]: https://competitions.cr.yp.to/round3/deoxysv141.pdf
