use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use lazy_static::lazy_static;

lazy_static! {
pub static ref  MODP_2048: BigUint = BigUint::parse_bytes("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF".as_bytes(), 16).unwrap();
}
pub fn DH_generate_key_pair(p : &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let mut rng = thread_rng();
    let private_key = rng.gen_biguint_range(&BigUint::from(2u32), p);
    let public_key = BigUint::modpow(g, &private_key, p);
    (private_key, public_key)
}
pub fn DH_shared_secret(private_key : &BigUint, others_public : &BigUint, p : &BigUint) -> BigUint {
    BigUint::modpow(others_public, private_key, p)
}