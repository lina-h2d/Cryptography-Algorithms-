use std::io;
use std::io::Write;
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use crate::asymmetric_encryption::utils::generate_safe_prime;
use crate::asymmetric_encryption::{outputBytes, parseHexBytes};

pub fn ElGamal_generate_keys(bit_size: u64, rounds : usize) -> (BigUint, BigUint,BigUint, BigUint) {
    let p = generate_safe_prime(bit_size,rounds);
    let mut rng = thread_rng();
    let g = BigUint::from(2u32);
    let private_key  = rng.gen_biguint_range(&BigUint::from(2u32), &(&p - &BigUint::from(2u32)));
    let public_key = g.modpow(&private_key, &p);
    (public_key, private_key,p, g)
}
pub fn ElGamal_encrypt(message : &BigUint, public_key: &BigUint, p : &BigUint, g : &BigUint) -> (BigUint, BigUint) {

    let mut rng = thread_rng();
    let i  = rng.gen_biguint_range(&BigUint::from(2u32), &(p - &BigUint::from(2u32)));
    let ephemeral_public_key = g.modpow(&i, p);
    let masking_public_key = public_key.modpow(&i, p);
    let ciphertext = (message * &masking_public_key) % p;
    (ciphertext, ephemeral_public_key)
}
pub fn ElGamal_decrypt(ciphertext: &BigUint, ephemeral_public_key: &BigUint, p: &BigUint, private_key: &BigUint) -> BigUint {
    let masking_public_key = ephemeral_public_key.modpow(private_key, p);
    let inverse_masking_public_key = masking_public_key.modinv(p).unwrap();
    (ciphertext * inverse_masking_public_key) % p
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let mut p_str = String::new();
    let mut g_str = String::new();
    let mut key_str = String::new();  // public key for encryption, private for decryption
    let r;

    const PREFIX: &str = "ElGamal/";

    PATH.push_str(PREFIX);
    r = super::getGenericOption(PATH.clone());
    if r == 3 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    // Get message input
    print!("Enter message as series of hex (ABCDE12...): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read message");
    let message = BigUint::parse_bytes(buf.trim().as_bytes(), 16)
        .expect("Failed to parse message");

    // Get prime modulus (p)
    print!("Enter prime modulus (p) as hex: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut p_str).expect("Failed to read p");
    let p = BigUint::parse_bytes(p_str.trim().as_bytes(), 16)
        .expect("Failed to parse p");

    // Get generator (g)
    print!("Enter generator (g) as hex: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut g_str).expect("Failed to read g");
    let g = BigUint::parse_bytes(g_str.trim().as_bytes(), 16)
        .expect("Failed to parse g");

    // Get key (public for encryption, private for decryption)
    let prompt = if r == 1 {
        "Enter recipient's public key as hex: "
    } else {
        "Enter your private key as hex: "
    };
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut key_str).expect("Failed to read key");
    let key = BigUint::parse_bytes(key_str.trim().as_bytes(), 16)
        .expect("Failed to parse key");

    let output = match r {
        1 => {
            let (c1, c2) = ElGamal_encrypt(&message, &key, &p, &g);
            println!("\nCiphertext components:");
            println!("c1: {:X}", c1);
            println!("c2: {:X}", c2);
            vec![c1.to_bytes_be(), c2.to_bytes_be()].concat()
        },
        2 => {
            let message = message.to_bytes_be();
            // For decryption, we need to split input into two components
            let half = message.len() / 2;
            let (c1_bytes, c2_bytes) = message.split_at(half);
            let c1 = BigUint::from_bytes_be(c1_bytes);
            let c2 = BigUint::from_bytes_be(c2_bytes);

            let plaintext = ElGamal_decrypt(&c1, &c2, &p, &key);
            plaintext.to_bytes_be()
        },
        _ => panic!("Undefined Encryption/Decryption choice."),
    };

    print!("\nResult: ");          outputBytes(output);

    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}