use rand::Rng;
use crate::classical_ciphers::vigenere::{decrypt_vigenere, encrypt_vigenere};

pub fn generate_otp_key(length: usize) -> String{
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            (b'A' + rng.gen_range(0..26)) as char
        })
        .collect()
}
pub fn encrypt_otp(plaintext: &str) -> (String, String){
    let key = generate_otp_key(plaintext.len());
    (encrypt_vigenere(&plaintext, &key), key)
}
pub fn decrypt_otp(plaintext: &str, key: &str) -> String{
    decrypt_vigenere(&plaintext, &key)
}