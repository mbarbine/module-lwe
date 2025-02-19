use criterion::{criterion_group, criterion_main, Criterion};
use module_lwe::keygen::keygen;
use module_lwe::utils::Parameters;

fn bench_keygen(c: &mut Criterion) {
    let params = Parameters::default();
    c.bench_function("keygen", |b| {
        b.iter(|| keygen(&params, None))
    });
}

criterion_group!(benches, bench_keygen);
criterion_main!(benches);