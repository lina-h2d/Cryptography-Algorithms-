use std::io;
use std::io::Write;
use crate::asymmetric_encryption::utils::{mod_inverse, BigUint_GCD, generate_safe_prime};
use num_bigint::BigUint;
use num_traits::One;
use rand::{thread_rng, Rng};
use crate::asymmetric_encryption::{outputBytes, parseHexBytes};

const MAX_ATTEMPTS: usize = 100;

pub fn rsa_generate_key_pair(bits: u64, rounds: usize) -> (BigUint, BigUint, BigUint) {
    let e = BigUint::from(65537u32);
    for _iteration in 1..MAX_ATTEMPTS + 1 {
        let p = generate_safe_prime(bits / 2, rounds);
        let q = generate_safe_prime(bits / 2, rounds);

        if p == q { continue; }

        let n = &p * &q;
        let phi = (&p - BigUint::one()) * (&q - BigUint::one());

        if BigUint_GCD(e.clone(), phi.clone()) == BigUint::one() {
            if let Some(d) = mod_inverse(e.clone(), phi.clone()) {
                if &d < &n {
                    return (n, e, d);
                }
            }
        }
    }
    panic!("Failed to generate RSA key pair after {} attempts.", MAX_ATTEMPTS);
}

// PKCS#1 v1.5 Padding
fn pkcs1_v1_5_pad(message: &Vec<u8>, k: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut padded = vec![0x00, 0x02];

    // Add random non-zero bytes
    padded.extend((0..k - message.len() - 3).map(|_| rng.gen_range(1..=255)));
    padded.push(0x00);
    padded.extend(message);
    padded
}

// PKCS#1 v1.5 Unpadding
fn pkcs1_v1_5_unpad(padded: &Vec<u8>) -> Vec<u8> {
    if padded.len() < 11 || padded[0] != 0x00 || padded[1] != 0x02 {
        panic!("Invalid Padding"); // Invalid padding
    }

    // Find the separator (0x00 after random bytes)
    let sep_pos = match padded[2..].iter().position(|&b| b == 0x00) {
        None => panic!("Invalid Padding, couldn't find terminating null byte."),
        Some(index) => index + 2,   // for 2 bytes that we skipped in search
    };

    padded[sep_pos + 1..].to_vec()
}

pub fn encrypt(cleartext: &Vec<u8>, e: &BigUint, n: &BigUint) -> Vec<u8> {
    let k = (n.bits() + 7) / 8; // Key size in bytes

    let padded = pkcs1_v1_5_pad(cleartext, k as usize);

    let m = BigUint::from_bytes_be(padded.as_slice());

    if m > *n { panic!("m '0x{m:X}' is bigger than modulus n '0x{n:X}'."); }
    let c = m.modpow(&e, &n);

    c.to_bytes_be().to_vec()
}

pub fn decrypt(ciphertext: &Vec<u8>, d: &BigUint, n: &BigUint) -> Vec<u8> {
    let mut rslt: Vec<u8> = Vec::new();

    let c = BigUint::from_bytes_be(ciphertext);
    let m = c.modpow(&d, &n);
    let m = m.to_bytes_be().to_vec();

    // First null byte of padding usually removed by to_bytes_be()
    if m[0] != 0x00 { rslt.push(0x00); }
    rslt.extend(m);

    pkcs1_v1_5_unpad(&rslt)
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let mut modulus = String::new();
    let mut exponent = String::new(); // e or d, depends on context
    let r;
    
    const PREFIX: &str = "RSA/";

    PATH.push_str(PREFIX);
    r = super::getGenericOption(PATH.clone());
    if r == 3 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    print!("Enter text as series of hex (ABCDE12...): ");               io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read plaintext");
    let buf = parseHexBytes(buf);
    
    print!("Enter exponent (e or d, depends on encryption/decryption) as series of hex (ABCDE12...): ");                  io::stdout().flush().unwrap();
    io::stdin().read_line(&mut exponent).expect("Failed to read exponent");
    let exponent = BigUint::parse_bytes(exponent.trim().as_bytes(), 16).expect("Failed to parse exponent.");
    
    print!("Enter n (the modulus) as series of hex (ABCDE12...): ");                  io::stdout().flush().unwrap();
    io::stdin().read_line(&mut modulus).expect("Failed to read modulus");
    let modulus = BigUint::parse_bytes(modulus.trim().as_bytes(), 16).expect("Failed to parse modulus.");

    let output = match r {
        1 => encrypt(&buf, &exponent, &modulus),
        2 => decrypt(&buf, &exponent, &modulus),
        _ => panic!("Undefined Encryption/Decryption choice."),
    };

    print!("\nResult: ");       outputBytes(output);

    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}