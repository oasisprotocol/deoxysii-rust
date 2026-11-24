use deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE};

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use rand::{rngs::SysRng, TryRng};
use std::hint::black_box;

fn mrae_seal_4096(b: &mut Bencher) {
    let mut rng = SysRng;

    // Set up the key.
    let mut key = [0u8; KEY_SIZE];
    rng.try_fill_bytes(&mut key).unwrap();
    let d2 = DeoxysII::new(&key);

    // Set up the payload.
    let mut nonce = [0u8; NONCE_SIZE];
    rng.try_fill_bytes(&mut nonce).unwrap();
    let mut text = [0u8; 4096];
    rng.try_fill_bytes(&mut text).unwrap();
    let mut aad = [0u8; 64];
    rng.try_fill_bytes(&mut aad).unwrap();

    // Benchmark sealing.
    b.iter(|| {
        let text = text.to_vec();
        let aad = aad.to_vec();
        let _sealed = black_box(d2.seal(&nonce, text, aad));
    });
}

fn mrae_open_4096(b: &mut Bencher) {
    let mut rng = SysRng;

    // Set up the key.
    let mut key = [0u8; KEY_SIZE];
    rng.try_fill_bytes(&mut key).unwrap();
    let d2 = DeoxysII::new(&key);

    // Set up the payload.
    let mut nonce = [0u8; NONCE_SIZE];
    rng.try_fill_bytes(&mut nonce).unwrap();
    let mut text = [0u8; 4096];
    rng.try_fill_bytes(&mut text).unwrap();
    let mut aad = [0u8; 64];
    rng.try_fill_bytes(&mut aad).unwrap();

    // Seal the payload.
    let ciphertext = d2.seal(&nonce, text, aad);

    // Benchmark opening.
    b.iter(|| {
        let ct = ciphertext.to_vec();
        let aad = aad.to_vec();
        let _opened = black_box(d2.open(&nonce, ct, aad));
    });
}

fn mrae_new(b: &mut Bencher) {
    let mut rng = SysRng;

    // Set up the key.
    let mut key = [0u8; KEY_SIZE];
    rng.try_fill_bytes(&mut key).unwrap();

    b.iter(|| {
        let _d2 = black_box(DeoxysII::new(&key));
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("mrae_open_4096", mrae_open_4096);
    c.bench_function("mrae_seal_4096", mrae_seal_4096);
    c.bench_function("mrae_new", mrae_new);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
