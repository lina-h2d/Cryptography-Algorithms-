use std::collections::HashMap;
use std::io;
use std::io::Write;
use crate::classical_ciphers::caesar::decrypt_caesar;

pub const COMMON_ENGLISH_LETTERS: [char; 26] = [
    'E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 'L', 'C', 'U', 'M', 'W', 'F', 'G', 'Y', 'P', 'B', 'V', 'K', 'J', 'X', 'Q', 'Z',
];
pub const COMMON_FRENCH_LETTERS: [char; 26] = [
    'E', 'A', 'S', 'I', 'T', 'N', 'R', 'U', 'L', 'O', 'D', 'C', 'M', 'P', 'V', 'Q', 'F', 'B', 'G', 'H', 'J', 'X', 'Y', 'Z', 'K', 'W',
];

pub fn frequency_counter(ciphertext: &str) -> HashMap<char, usize> {
    let cleaned_ciphertext =  ciphertext.to_ascii_uppercase();
    let mut freq_table = HashMap::new();
    for  c in 'A'..='Z' {
        freq_table.insert(c, 0);
    }
    for c in cleaned_ciphertext.chars() {
        if let Some(freq) = freq_table.get_mut(&c) {
            *freq += 1;
        }
    }
    freq_table
}

pub fn decrypt_using_freq_analysis(ciphertext: &str) -> Vec<String> {
    let cleaned_ciphertext: String = ciphertext.chars()
        .filter(|c| c.is_alphabetic())
        .collect::<String>()
        .to_ascii_uppercase();

    let freq_table = frequency_counter(&cleaned_ciphertext);
    let max_freq = freq_table.values().cloned().max().unwrap();
    let most_freq_chars: Vec<char> = freq_table.iter()
        .filter(|&(_, &count)| count == max_freq)
        .map(|(&c, _)| c)
        .collect();

    let most_freq_char = 'E';
    let mut possible_decryptions = Vec::new();
    // println!("most freq chars : {:?}", most_freq_chars);
    for &most_freq_ciphertext_char in &most_freq_chars {
        let shift = (most_freq_ciphertext_char as u8).wrapping_sub(most_freq_char as u8) % 26;
        // println!(
        //     "Trying {} -> {} (shift: {})",
        //     most_freq_ciphertext_char, most_freq_english_char, shift
        // );
        let decryption = decrypt_caesar(ciphertext, shift);
        possible_decryptions.push(decryption);
    }
    possible_decryptions
}

fn printMenu(){
    println!("What do you want to do?");
    println!("1- Decrypt");
    println!("2- Return");
}

fn getOption(PATH: String) -> usize {
    printMenu();
    let r = super::getInput(PATH, 1, 2);
    println!();
    r
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let decryptions;
    const PREFIX: &str = "frequency_analysis/";

    PATH.push_str(PREFIX);
    let r = getOption(PATH.clone());
    if r == 2 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    print!("Enter text: ");                 io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read plaintext");

    decryptions = decrypt_using_freq_analysis(&buf);

    println!("\nPossible Decryptions:");
    for i in 0..decryptions.len() { println!("{}: {}", i + 1, decryptions[i]); }
    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}
