# deoxysii-rust - Deoxys-II-256-128 for Rust

[![CircleCI](https://circleci.com/gh/oasislabs/deoxysii-rust.svg?style=svg&circle-token=7b2=eb2bede060d972c153006a3023224eabdeca)]

This crate provides a Rust implementation of [Deoxys-II-256-128 v1.41][0].

The implementation uses Intel SIMD intrinsics (SSSE3 and AES-NI) for
speed and will therefore only run on relatively modern x86-64 processors.

The nightly version of Rust is required to build this crate.

To build everything, run tests and benchmarks, simply run `make`.

[0]: https://competitions.cr.yp.to/round3/deoxysv141.pdf
