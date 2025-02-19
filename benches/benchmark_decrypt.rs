use criterion::{criterion_group, criterion_main, Criterion};
use module_lwe::decrypt::decrypt;
use module_lwe::keygen::keygen;
use module_lwe::encrypt::encrypt;
use module_lwe::utils::Parameters;

fn bench_decrypt(c: &mut Criterion) {
    let params = Parameters::default();
    let (pk, sk) = keygen(&params, None);
    let m_b = vec![0, 1, 0, 1, 1, 0, 1, 0]; // Example binary message
    let (u, v) = encrypt(&pk.0, &pk.1, &m_b, &params, None);

    c.bench_function("decrypt", |b| {
        b.iter(|| decrypt(&sk, &u, &v, &params))
    });
}

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
