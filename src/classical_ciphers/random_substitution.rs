use std::collections::HashMap;
use rand::seq::SliceRandom;
pub fn generate_random_substitution_key() -> HashMap<char,char>{
    let mut rng = rand::thread_rng();
    let alphabet: Vec<char> = ('a'..='z').collect();
    let mut shuffled = alphabet.clone();
    shuffled.shuffle(&mut rng);
    alphabet.iter().zip(shuffled.iter()).map(|(&a, &b)| (a,b)).collect()
}

pub fn encrypt_random_substitution(plaintext: &str,key: &HashMap<char,char>) -> String{
    plaintext
        .chars()
        .map(|c|{
            if c.is_ascii_alphabetic() {
                let lowercase_c = c.to_ascii_lowercase();
                let substituted = key.get(&lowercase_c).unwrap_or(&lowercase_c);
                if c.is_ascii_uppercase() {
                    substituted.to_ascii_uppercase()
                } else {
                    *substituted
                }
            } else {
                c
            }
        })
        .collect()
}
pub fn decrypt_random_substitution(ciphertext: &str,key: &HashMap<char,char>) -> String{
    let reverse_key: HashMap<char,char> = key.iter().map(|(&k,&v)| (v,k)).collect();
    ciphertext
        .chars()
        .map(|c|{
            if c.is_ascii_alphabetic() {
                let lowercase_c = c.to_ascii_lowercase();
                let original = reverse_key.get(&lowercase_c).unwrap_or(&lowercase_c);
                if c.is_ascii_uppercase() {
                    original.to_ascii_uppercase()
                } else {
                    *original
                }
            } else {
                c
            }
        })
        .collect()
}