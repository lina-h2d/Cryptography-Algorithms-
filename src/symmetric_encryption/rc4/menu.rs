use std::io::{self, Write};
use crate::symmetric_encryption::rc4::{encrypt::encrypt, decrypt::decrypt, rc4::to_hex};
use super::super::menu::{outputBytes, parseHexBytes};

fn print_rc4_menu() {
    println!("Choose operation:");
    println!("1 - Encrypt");
    println!("2 - Decrypt");
    println!("3 - Return");
}

pub fn Menu(path: &mut String) -> usize {
    const PREFIX: &str = "RC4/";
    path.push_str(PREFIX);

    print_rc4_menu();
    let choice = super::getInput(path.clone(), 1, 3);

    if choice == 3 {
        path.drain(path.len() - PREFIX.len()..);
        return 1;
    }

    let mut data_input = String::new();
    let mut key_input = String::new();

    print!("Enter data as series of hex (e.g., 48656C6C6F): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut data_input).expect("Failed to read input");
    let data = parseHexBytes(data_input);

    print!("Enter key as series of hex (e.g., 6B6579): ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut key_input).expect("Failed to read key");
    let key = parseHexBytes(key_input);

    let result = match choice {
        1 => encrypt(&key, &data),
        2 => decrypt(&key, &data),
        _ => panic!("Invalid choice."),
    };

    print!("\nResult: ");
    outputBytes(result);

    path.drain(path.len() - PREFIX.len()..);
    0
}
