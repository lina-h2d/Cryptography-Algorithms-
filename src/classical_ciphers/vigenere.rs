use std::io;
use std::io::Write;
use crate::classical_ciphers::caesar::{encrypt_caesar, decrypt_caesar};

pub fn encrypt_vigenere(plaintext: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();
    let mut i = 0;

    plaintext.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let key_char = key_bytes[i % key_len];
                let shift = if key_char.is_ascii_lowercase() {
                    key_char - b'a'
                } else {
                    key_char - b'A'
                };
                let encrypted_char = encrypt_caesar(&c.to_string(), shift);
                i += 1;
                encrypted_char.chars().next().unwrap()
            } else {
                c
            }
        })
        .collect()
}
pub fn decrypt_vigenere(ciphertext: &str, key: &str) -> String {
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();
    let mut i = 0;

    ciphertext.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let key_char = key_bytes[i % key_len];
                let shift = if key_char.is_ascii_lowercase() {
                    key_char - b'a'
                } else {
                    key_char - b'A'
                };
                let encrypted_char = decrypt_caesar(&c.to_string(), shift);
                i += 1;
                encrypted_char.chars().next().unwrap()
            } else {
                c
            }
        })
        .collect()
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let mut key = String::new();
    let r;
    const PREFIX: &str = "playfair/";

    PATH.push_str(PREFIX);
    r = super::getGenericOption(PATH.clone());
    if r == 3 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    print!("Enter text: ");                 io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read plaintext");
    buf = buf.trim().to_string();

    print!("Enter key: ");                  io::stdout().flush().unwrap();
    io::stdin().read_line(&mut key).expect("Failed to read key");
    key = key.trim().to_string();

    match r {
        1 => buf = encrypt_vigenere(buf.as_str(), key.as_str()),
        2 => buf = decrypt_vigenere(buf.as_str(), key.as_str()),
        _ => {}
    }

    println!("\nResult: {buf}");
    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}