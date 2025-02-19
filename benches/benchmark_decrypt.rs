use criterion::{criterion_group, criterion_main, Criterion};
use module_lwe::decrypt::{decrypt,decrypt_string};
use module_lwe::keygen::{keygen,keygen_string};
use module_lwe::encrypt::{encrypt,encrypt_string};
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

fn bench_decrypt_string(c: &mut Criterion) {
    let params = Parameters::default();
    let keypair = keygen_string(&params, None);
    let sk_string = keypair.get("secret").unwrap();
    let pk_string = keypair.get("public").unwrap();
    let message = String::from("hello");
    let ciphertext_string = encrypt_string(&pk_string, &message, &params, None);
    
    c.bench_function("decrypt_string", |b| {
        b.iter(|| decrypt_string(&sk_string, &ciphertext_string, &params))
    });
}

criterion_group!(benches, bench_decrypt, bench_decrypt_string);
criterion_main!(benches);
