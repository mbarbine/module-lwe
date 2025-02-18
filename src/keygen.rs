use polynomial_ring::Polynomial;
use std::collections::HashMap;
use crate::utils::{Parameters, add_vec, mul_mat_vec_simple, gen_small_vector, gen_uniform_matrix};

/// Generate public and secret keys for the ring-LWE cryptosystem
/// # Arguments
/// * `params` - Parameters for the ring-LWE cryptosystem
/// * `seed` - random seed
/// # Returns
/// * `((a, t), sk)` - public key (a, t) and secret key (sk)
/// # Example
/// ```
/// let params = module_lwe::utils::Parameters::default();
/// let (pk, sk) = module_lwe::keygen::keygen(&params, None);
/// ```
pub fn keygen(
	params: &Parameters,
    seed: Option<u64> //random seed
) -> ((Vec<Vec<Polynomial<i64>>>, Vec<Polynomial<i64>>), Vec<Polynomial<i64>>) {
    let (n,q,k,f) = (params.n, params.q, params.k, &params.f);
    //Generate a public and secret key
    let a = gen_uniform_matrix(n, k, q, seed);
    let sk = gen_small_vector(n, k, seed);
    let e = gen_small_vector(n, k, seed);
    let t = add_vec(&mul_mat_vec_simple(&a, &sk, q, &f), &e, q, &f);
    
    //Return public key (a, t) and secret key (sk) as a 2-tuple
    ((a, t), sk)
}

/// Generate public and secret keys for the ring-LWE cryptosystem and return them as a HashMap
/// # Arguments
/// * `params` - Parameters for the ring-LWE cryptosystem
/// * `seed` - random seed
/// # Returns
/// * `keys` - HashMap containing the public and secret keys
/// # Example
/// ```
/// let params = module_lwe::utils::Parameters::default();
/// let keys = module_lwe::keygen::keygen_string(&params, None);
/// ```
pub fn keygen_string(params: &Parameters, seed: Option<u64>) -> HashMap<String, String> {

    //generate public, secret keys
    let (pk,sk) = keygen(params,seed);

    // Convert public key to a flattened list of coefficients
    let mut pk_coeffs: Vec<i64> = pk.0
        .iter()
        .flat_map(|row| {
            row.iter().flat_map(|poly| {
                let mut coeffs = poly.coeffs().to_vec();
                coeffs.resize(params.n, 0); // Resize to include leading zeros up to size `n`
                coeffs
            })
        })
        .collect();
    pk_coeffs.extend(
        pk.1.iter()
        .flat_map(|poly| {
            let mut coeffs = poly.coeffs().to_vec();
            coeffs.resize(params.n, 0); // Resize to include leading zeros up to size `n`
            coeffs
        })
    );

    // Convert secret key to a flattened list of coefficients
    let sk_coeffs: Vec<i64> = sk
        .iter()
        .flat_map(|poly| {
            let mut coeffs = poly.coeffs().to_vec();
            coeffs.resize(params.n, 0); // Resize to include leading zeros up to size `n`
            coeffs
        })
    .collect();

    // Convert the public/secret key coefficients to a comma-separated string
    let pk_coeffs_str = pk_coeffs.iter()
        .map(|coef| coef.to_string())
        .collect::<Vec<String>>()
        .join(",");
    let sk_coeffs_str = sk_coeffs.iter()
        .map(|coef| coef.to_string())
        .collect::<Vec<String>>()
        .join(",");
    
    //store the secret/public key in a HashMap
    let mut keys: HashMap<String, String> = HashMap::new();
    keys.insert(String::from("secret"), sk_coeffs_str);
    keys.insert(String::from("public"), pk_coeffs_str);
    
    keys
}