use std::io;
use std::io::Write;
use num::integer::{gcd};
use modinverse::modinverse;

const ALPHABET_SIZE: u8 = 26;
pub fn encrypt_affine(plaintext: &str, a : u8, b : u8) -> String {
    if gcd(a, ALPHABET_SIZE) != 1 {
        panic!("Key `a` must be coprime with the alphabet size (26).");
    }
    plaintext.chars().map(|c| {
        if c.is_ascii_alphabetic(){
            let x = c.to_ascii_uppercase() as u8 - 'A' as u8;
            let y = (a * x + b) % ALPHABET_SIZE as u8;
            (y + 'A' as u8) as char
        }else{
            c
        }
    }).collect()
}
pub fn decrypt_affine(ciphertext: &str, a : u8, b : u8) -> String {
    if gcd(a, ALPHABET_SIZE) != 1 {
        panic!("Key `a` must be coprime with the alphabet size (26).");
    }
    let a_inv = modinverse(a as i64, ALPHABET_SIZE as i64).unwrap() as u16;
    ciphertext.chars().map(|c| {
        if c.is_ascii_alphabetic(){
            let y = c.to_ascii_uppercase() as u16 - 'A' as u16;
            let x = (((y + ALPHABET_SIZE  as u16 - b as u16 ) * a_inv) % ALPHABET_SIZE as u16) as u8;
            (x + 'A' as u8) as char
        }else{
            c
        }
    }).collect()
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let mut a = String::new();
    let mut b = String::new();
    let r;
    const PREFIX: &str = "affine/";

    PATH.push_str(PREFIX);
    r = super::getGenericOption(PATH.clone());
    match r {
        1 => println!("Encryption Formula: E(x) = (ax + b) mod m"),
        2 => println!(r#"Decryption Formula: D(x) = (a⁻¹) * (x - b) mod m"#),
        3 => {
            PATH.drain(PATH.len() - PREFIX.len()..);
            return 1;
        },
        _ => {}
    }
    
    print!("Enter text: ");                 io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read plaintext.");

    print!("Enter a (must be coprime with the alphabet size (26)): "); io::stdout().flush().unwrap();
    io::stdin().read_line(&mut a).expect("Failed to read 'a'.");
    let a = a.trim().parse::<u8>().expect("Invalid number.");

    print!("Enter b: ");                    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut b).expect("Failed to read 'b'.");
    let b = b.trim().parse::<u8>().expect("Invalid number.");
    
    match r {
        1 => buf = encrypt_affine(buf.as_str(), a, b),
        2 => buf = decrypt_affine(buf.as_str(), a, b),
        _ => {}
    }

    println!("\nResult: {buf}");
    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}