use std::io;
use std::io::Write;
use crate::symmetric_encryption::aes::aes_decryption::{decrypt_cbc, decrypt_ecb};
use crate::symmetric_encryption::aes::aes_encryption::{encrypt_cbc, encrypt_ecb};
use super::super::menu::{outputBytes, parseHexBytes};

fn printModesMenu(){
    println!("Choose mode:");
    println!("1- ECB");
    println!("2- CBC");
    println!("3- Return");
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let mut key = String::new();
    let mut iv = String::new();
    let mut iv_arr: [u8; 16] = [0; 16];
    let r;
    let m;
    const PREFIX: &str = "AES/";

    PATH.push_str(PREFIX);
    r = super::getGenericOption(PATH.clone());
    if r == 3 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    printModesMenu();
    m = super::getInput(PATH.clone(), 1, 3);
    if m == 3 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    print!("Enter text as series of hex (ABCDE12...): ");               io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read plaintext");
    let buf = parseHexBytes(buf);

    print!("Enter key as series of hex (ABCDE12...): ");                  io::stdout().flush().unwrap();
    io::stdin().read_line(&mut key).expect("Failed to read key");
    let key: [u8; 16] = match parseHexBytes(key).try_into() {
        Ok(k) => k,
        Err(t) => panic!("Key length must be 16 but got '{}'.", t.len()),
    };

    if m == 2 {
        print!("Enter IV as series of hex (ABCDE12...): ");               io::stdout().flush().unwrap();
        io::stdin().read_line(&mut iv).expect("Failed to read plaintext");
        iv_arr = match parseHexBytes(iv).try_into() {
            Ok(k) => k,
            Err(t) => panic!("IV length must be 16 but got '{}'.", t.len()),
        };
    }

    let output = match r {
        1 => match m {
                1 => encrypt_ecb(buf, &key),
                2 => encrypt_cbc(&buf, &iv_arr, &key),
                _ => panic!("Undefined mode for Encryption."),
            },
        2 => match m {
                1 => decrypt_ecb(&buf, &key),
                2 => decrypt_cbc(buf, &iv_arr, &key),
                _ => panic!("Undefined mode"),
            }.expect("Undefined mode for Decryption."),
        _ => panic!("Undefined Encryption/Decryption choice."),
    };

    print!("\nResult: ");       outputBytes(output);
    
    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}