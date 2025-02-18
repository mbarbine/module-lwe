use polynomial_ring::Polynomial;
use rand_distr::{Uniform, Distribution};
use rand::SeedableRng;
use rand::rngs::StdRng;
use ring_lwe::{polyadd, polymul, gen_uniform_poly};

#[derive(Debug)]
/// default parameters for module-LWE
pub struct Parameters {
	/// degree of the polynomials
    pub n: usize,
	/// Ciphertext modulus
    pub q: i64,
	/// Plaintext modulus    
    pub k: usize,     
	/// Polynomial modulus
    pub f: Polynomial<i64>, 
}

/// default parameters for module-LWE
impl Default for Parameters {
    fn default() -> Self {
        let n = 32;
        let q = 59049;
        let k = 8;
        let mut poly_vec = vec![0i64;n+1];
        poly_vec[0] = 1;
        poly_vec[n] = 1;
        let f = Polynomial::new(poly_vec);
        Parameters { n, q, k, f }
    }
}

/// add two vectors of polynomials
/// # Arguments
/// * `v0` - vector of polynomials
/// * `v1` - vector of polynomials
/// * `modulus` - modulus
/// * `poly_mod` - polynomial modulus
/// # Returns
/// * `result` - vector of polynomials
pub fn add_vec(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>) -> Vec<Polynomial<i64>> {
	assert!(v0.len() == v1.len());
	let mut result = vec![];
	for i in 0..v0.len() {
		result.push(polyadd(&v0[i], &v1[i], modulus, &poly_mod));
	}
	result
}

/// take the dot product of two vectors of polynomials
/// # Arguments
/// * `v0` - vector of polynomials
/// * `v1` - vector of polynomials
/// * `modulus` - modulus
/// * `poly_mod` - polynomial modulus
/// # Returns
/// * `result` - polynomial
pub fn mul_vec_simple(v0: &Vec<Polynomial<i64>>, v1: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>) -> Polynomial<i64> {
	assert!(v0.len() == v1.len());
	let mut result = Polynomial::new(vec![]);
	for i in 0..v0.len() {
		result = polyadd(&result, &polymul(&v0[i], &v1[i], modulus, &poly_mod), modulus, &poly_mod);
	}
	result
}

/// multiply a matrix by a vector of polynomials
/// # Arguments
/// * `m` - matrix of polynomials
/// * `v` - vector of polynomials
/// * `modulus` - modulus
/// * `poly_mod` - polynomial modulus
/// # Returns
/// * `result` - vector of polynomials
pub fn mul_mat_vec_simple(m: &Vec<Vec<Polynomial<i64>>>, v: &Vec<Polynomial<i64>>, modulus: i64, poly_mod: &Polynomial<i64>) -> Vec<Polynomial<i64>> {
	
	let mut result = vec![];
	for i in 0..m.len() {
		result.push(mul_vec_simple(&m[i], &v, modulus, &poly_mod));
	}
	result
}

/// take the transpose of a matrix of polynomials
/// # Arguments
/// * `m` - matrix of polynomials
/// # Returns
/// * `result` - matrix of polynomials
pub fn transpose(m: &Vec<Vec<Polynomial<i64>>>) -> Vec<Vec<Polynomial<i64>>> {
	let mut result = vec![vec![Polynomial::new(vec![]); m.len()]; m[0].len()];
	for i in 0..m.len() {
		for j in 0..m[0].len() {
			result[j][i] = m[i][j].clone();
		}
	}
	result
}

/// generates a vector of given rank of degree size-1 polynomials with coefficients in {-1,0,1}
/// # Arguments
/// * `size` - degree of the polynomials
/// * `rank` - rank of the vector
/// * `seed` - seed for the random number generator
/// # Returns
/// * `v` - vector of polynomials
pub fn gen_small_vector(size : usize, rank: usize, seed: Option<u64>) -> Vec<Polynomial<i64>> {
	let mut v = vec![];
	let between = Uniform::new(0,3);
	let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let mut coeffs = vec![0i64;size];
	for _i in 0..rank {
		for j in 0.. size {
			coeffs[j] = between.sample(&mut rng)-1;
		}
		v.push(Polynomial::new(coeffs.clone()));
	}
	v
}

/// generates a `rank x rank` matrix of degree `size-1` polynomials with uniform coefficients in Z_modulus
/// # Arguments
/// * `size` - degree of the polynomials
/// * `rank` - rank of the matrix
/// * `modulus` - modulus
/// * `seed` - seed for the random number generator
/// # Returns
/// * `m` - matrix of polynomials
pub fn gen_uniform_matrix(size : usize, rank: usize, modulus: i64, seed: Option<u64>) -> Vec<Vec<Polynomial<i64>>> {
	let mut m = vec![vec![Polynomial::new(vec![]); rank]; rank];
	for i in 0..rank {
		for j in 0..rank {
			m[i][j] = gen_uniform_poly(size, modulus, seed);
		}
	}
	m
}
	