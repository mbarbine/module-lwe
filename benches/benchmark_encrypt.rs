use criterion::{criterion_group, criterion_main, Criterion};
use module_lwe::encrypt::encrypt;
use module_lwe::keygen::keygen;
use module_lwe::utils::Parameters;

fn bench_encrypt(c: &mut Criterion) {
    let params = Parameters::default();
    let (pk, _) = keygen(&params, None);
    let m_b = vec![0, 1, 0, 1, 1, 0, 1, 0]; // Example binary message

    c.bench_function("encrypt", |b| {
        b.iter(|| encrypt(&pk.0, &pk.1, &m_b, &params, None))
    });
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);