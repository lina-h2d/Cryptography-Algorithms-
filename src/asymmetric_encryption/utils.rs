use num::Integer;
use std::cmp::min;
use std::mem::swap;
use num_bigint::Sign;
use miller_rabin::is_prime;
use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{One, Zero};

// Binary GCD (Stein's algorithm), taken directly from Wikipedia and implemented with BigUint: https://en.wikipedia.org/wiki/Binary_GCD_algorithm#Implementation
// Equivalent to PGCD(u, v)
pub fn BigUint_GCD(u: BigUint, v: BigUint) -> BigUint {
    let mut u = u.clone();
    let mut v = v.clone();

    // Base cases: gcd(n, 0) = gcd(0, n) = n
    if u.is_zero() { return v; }
    else if v .is_zero() { return u; }

    // Using identities 2 and 3:
    // gcd(2ⁱ u, 2ʲ v) = 2ᵏ gcd(u, v) with u, v odd and k = min(i, j)
    // 2ᵏ is the greatest power of two that divides both 2ⁱ u and 2ʲ v
    let i = u.trailing_zeros().unwrap() as usize;   u >>= i;
    let j = v.trailing_zeros().unwrap() as usize;   v >>= j;

    let k = min(i, j);
    loop {
        // u and v are odd at the start of the loop
        debug_assert!(u.is_odd(), "u = {} should be odd", u);
        debug_assert!(v.is_odd(), "v = {} should be odd", v);

        // Swap if necessary so u ≤ v
        if u > v { swap(&mut u, &mut v); }

        // Identity 4: gcd(u, v) = gcd(u, v-u) as u ≤ v and u, v are both odd
        v -= u.clone();
        // v is now even

        if v.is_zero() {
            // Identity 1: gcd(u, 0) = u
            // The shift by k is necessary to add back the 2ᵏ factor that was removed before the loop
            return u << k;
        }

        // Identity 3: gcd(u, 2ʲ v) = gcd(u, v) as u is odd
        v >>= v.trailing_zeros().unwrap() as usize;
    }
}

// fn extended_gcd_0(A: BigUint, B: BigUint) -> (BigUint, BigUint, BigUint) {
// Got pseudocode from Wikipedia, and converted it to rust: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
pub fn extended_gcd(a: BigUint, b: BigUint) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (BigInt::from_biguint(Sign::Plus, a), BigInt::from_biguint(Sign::Plus, b));
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

    while !r.is_zero() {
        let quotient = &old_r / &r;
        (old_r, r) = (r.clone(), old_r - &quotient * r);
        (old_s, s) = (s.clone(), old_s - &quotient * s);
        (old_t, t) = (t.clone(), old_t - &quotient * t);
    }

    (old_r, old_s, old_t)
}

// No need to verify gcd(e, phi) = 1, verification done outside function
pub fn mod_inverse(e: BigUint, phi: BigUint) -> Option<BigUint> {
    let (gcd, d, _) = extended_gcd(e.clone(), phi.clone());

    // Check GCD == 1 for existence
    if gcd != BigInt::one() { return None; }

    // Convert phi to BigInt for modulo operation
    let s_phi = BigInt::from_biguint(Sign::Plus, phi);

    // Compute d mod phi (handles negative values)
    let mut d_positive = d % s_phi.clone();
    if d_positive < BigInt::zero() {
        d_positive += s_phi.clone();
    }

    // Convert back to BigUint (now guaranteed positive)
    d_positive.to_biguint()
}

pub fn generate_safe_prime(bit_size: u64, rounds: usize) -> BigUint {
    let max_attempts = match bit_size {
        512 => 500_000,
        1024 => 2_000_000,
        2048 => 10_000_000,
        3072 => 30_000_000,
        4096 => 100_000_000,
        _ => 10_000_000,
    };
    
    let mut rng = rand::thread_rng();
    for _iteration in 1..max_attempts + 1 {
        let mut q = rng.gen_biguint(bit_size - 1);
        q.set_bit(bit_size - 2, true);// Ensure bit length
        q.set_bit(0, true); // Make odd

        if !is_prime(&q, rounds) { continue; }

        // check if 2q + 1 is prime
        let p = &q * BigUint::from(2u32) + BigUint::one();

        if is_prime(&p, rounds) { return p; }
        
        // if iteration % 1000 == 0 {
        //     println!("passed {} attempts", iteration);
        // }
    }
    
    panic!("failed to generate a safe prime after {} attempts", max_attempts);
}