use polynomial_ring::Polynomial;
use ring_lwe::utils::{polyadd,polysub,nearest_int};
use crate::utils::{Parameters, add_vec, mul_mat_vec_simple, transpose, mul_vec_simple, gen_small_vector};

/// Encrypt a message using the ring-LWE cryptosystem
/// # Arguments
/// * `a` - public key matrix
/// * `t` - public key vector
/// * `m_b` - binary message
/// * `params` - Parameters for the ring-LWE cryptosystem
/// * `seed` - random seed
/// # Returns
/// * `(u, v)` - ciphertext
/// # Example
/// ```
/// let params = module_lwe::utils::Parameters::default();
/// let (pk,sk) = module_lwe::keygen::keygen(&params, None);
/// let m_b = vec![0,1,0,1,1,0,1,0];
/// let (u, v) = module_lwe::encrypt::encrypt(&pk.0, &pk.1, &m_b, &params, None);
/// ```
pub fn encrypt(
    a: &Vec<Vec<Polynomial<i64>>>,
    t: &Vec<Polynomial<i64>>,
    m_b: &Vec<i64>,
    params: &Parameters,
    seed: Option<u64>
) -> (Vec<Polynomial<i64>>, Polynomial<i64>) {

    //get parameters
    let (n, q, k, f, omega) = (params.n, params.q, params.k, &params.f, params.omega);
    
    //generate random ephermal keys
    let r = gen_small_vector(n, k, seed);
    let e1 = gen_small_vector(n, k, seed);
    let e2 = gen_small_vector(n, 1, seed)[0].clone(); // Single polynomial

    //compute nearest integer to q/2
    let half_q = nearest_int(q,2);

    // Convert binary message to polynomial
    let m = Polynomial::new(vec![half_q])*Polynomial::new(m_b.to_vec());

    // Compute u = a^T * r + e_1 mod q
    let u = add_vec(&mul_mat_vec_simple(&transpose(a), &r, q, f, omega), &e1, q, f);

    // Compute v = t * r + e_2 - m mod q
    let v = polysub(&polyadd(&mul_vec_simple(t, &r, q, &f, omega), &e2, q, f), &m, q, f);

    (u, v)
}

/// function to encrypt a message given a public_key string
/// # Arguments
/// * `pk_string` - public key string
/// * `message_string` - message string
/// * `params` - Parameters for the ring-LWE cryptosystem
/// * `seed` - random seed
/// # Returns
/// * `ciphertext_str` - ciphertext string
/// # Example
/// ```
/// let params = module_lwe::utils::Parameters::default();
/// let keypair = module_lwe::keygen::keygen_string(&params,None);
/// let pk_string = keypair.get("public").unwrap();
/// let sk_string = keypair.get("secret").unwrap();
/// let message_string = "Hello, world!".to_string();
/// let ciphertext_string = module_lwe::encrypt::encrypt_string(&pk_string, &message_string, &params, None);
/// ```
pub fn encrypt_string(pk_string: &String, message_string: &String, params: &Parameters, seed: Option<u64>) -> String {

    //get parameters
    let (n, k) = (params.n, params.k);

    // Parse public key
    
    let pk_list: Vec<i64> = pk_string.split(',').map(|x| x.parse::<i64>().unwrap()).collect();

    let a: Vec<Vec<Polynomial<i64>>> = pk_list[..k * k * n]
        .chunks(k * n)
        .map(|chunk| {
            chunk.chunks(n).map(|coeffs| Polynomial::new(coeffs.to_vec())).collect()
        })
        .collect();

    let t: Vec<Polynomial<i64>> = pk_list[k * k * n..]
        .chunks(n)
        .map(|coeffs| Polynomial::new(coeffs.to_vec()))
        .collect();

    // Parse message
    let message_binary: Vec<i64> = message_string
        .bytes()
        .flat_map(|byte| (0..8).rev().map(move |i| ((byte >> i) & 1) as i64))
        .collect();

    // Break message into blocks, including the last partial block if necessary
    let message_blocks: Vec<Vec<i64>> = message_binary
        .chunks(n) // Divide the binary message into chunks of size `n`
        .map(|chunk| chunk.to_vec()) // Convert each chunk into a vector
        .collect();

    // Encrypt each block
    let mut ciphertext_list = vec![];
    for block in message_blocks {
        let (u, v) = encrypt(&a, &t, &block, params, seed);
        let u_flattened: Vec<i64> = u.iter()
            .flat_map(|poly| {
                let mut coeffs = poly.coeffs().to_vec();
                coeffs.resize(n, 0); // Resize to include leading zeros up to size `n`
                coeffs
            })
            .collect();
        let mut v_flattened: Vec<i64> = v.coeffs().to_vec();
        v_flattened.resize(n,0);
        ciphertext_list.extend(u_flattened);
        ciphertext_list.extend(v_flattened);
    }

    let ciphertext_str = ciphertext_list.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(",");

    ciphertext_str
}