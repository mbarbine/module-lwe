#[cfg(test)]  // This makes the following module compile only during tests
mod tests {
    use crate::keygen::{keygen,keygen_string};
    use crate::encrypt::{encrypt,encrypt_string};
    use crate::decrypt::{decrypt,decrypt_string};
    use module_lwe::{Parameters,gen_small_vector,add_vec};

    // Test for basic keygen/encrypt/decrypt of a message
    #[test]
    pub fn test_basic() {
        let seed = None; //set random seed
        let message = String::from("hello");
        let params = Parameters::default();  // Adjust this if needed
        let keypair = keygen_string(&params,seed);
        let pk_string = keypair.get("public").unwrap();
        let sk_string = keypair.get("secret").unwrap();
        let ciphertext_string = encrypt_string(&pk_string, &message, &params,seed);
        let decrypted_message = decrypt_string(&sk_string, &ciphertext_string, &params);
        assert_eq!(message, decrypted_message, "test failed: {} != {}", message, decrypted_message);
    }

    // Test homomorphic addition property: ensure sum of encrypted plaintexts decrypts to plaintext sum
    #[test]
    pub fn test_hom_add() {

        let seed = None; //set the random seed
        let params = Parameters::default();
        let (n, q, k, f) = (params.n, params.q, params.k, &params.f);

        // Randomly generated values for r, e1, and e2
        let r = gen_small_vector(n, k, seed);
        let e1 = gen_small_vector(n, k, seed);
        let e2 = gen_small_vector(n, 1, seed)[0].clone(); // Single polynomial

        let mut m0 = vec![0i64; n];
        m0[0] = 10;
        let mut m1 = vec![0i64; n];
        m1[0] = 5;
        let mut plaintext_sum = vec![0i64; n];
        plaintext_sum[0] = m0[0] + m1[0];
        let (pk, sk) = keygen(&params,seed);

        // Encrypt plaintext messages
        let u = encrypt(&pk.0, &pk.1, m0, f, q, &r, &e1, &e2);
        let v = encrypt(&pk.0, &pk.1, m1, f, q, &r, &e1, &e2);

        // Compute sum of encrypted data
        let ciphertext_sum = (add_vec(&u.0,&v.0,q,f), &u.1 + &v.1);

        // Decrypt ciphertext sum u+v
        let decrypted_sum = decrypt(&sk, q, f, &ciphertext_sum.0, &ciphertext_sum.1);
        println!("{:?}",decrypted_sum);

        assert_eq!(decrypted_sum, plaintext_sum, "test failed: {:?} != {:?}", decrypted_sum, plaintext_sum);
    }
}