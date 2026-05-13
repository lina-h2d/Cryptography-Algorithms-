use std::io;
use std::io::Write;

const ALPHABET_SIZE: u8 = 26;
pub fn encrypt_caesar(plaintext: &str, shift: u8) -> String {
    plaintext.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() {b'a'} else {b'A'};
                let offset = ((c as u8) - base + shift)  % ALPHABET_SIZE;
                (base + offset) as char
            } else {
                c
            }
        })
        .collect()
}
pub fn decrypt_caesar(plaintext: &str,shift: u8) -> String {
    encrypt_caesar(plaintext, ALPHABET_SIZE - (shift % ALPHABET_SIZE))
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let mut shift = String::new();
    let r;
    const PREFIX: &str = "caesar/";

    PATH.push_str(PREFIX);
    r = super::getGenericOption(PATH.clone());
    if r == 3 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    print!("Enter text: ");               io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read plaintext");

    print!("Enter size of shift: ");      io::stdout().flush().unwrap();
    io::stdin().read_line(&mut shift).expect("Failed to read shift size");
    let shift = shift.trim().parse::<u8>().expect("Invalid shift number");

    match r {
        1 => buf = encrypt_caesar(buf.as_str(), shift),
        2 => buf = decrypt_caesar(buf.as_str(), shift),
        _ => {}
    }

    println!("\nResult: {buf}");
    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}