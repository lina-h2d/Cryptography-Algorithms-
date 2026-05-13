use std::collections::HashMap;

// Frequencies of letters in typical English text, in percentage
const ENGLISH_LETTER_FREQUENCIES: [f64; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074,
];

// Clean the input by removing non-alphabetic characters and converting to uppercase
pub fn clean_input(text: &str) -> String {
    let mut cleaned_text = String::new();

    for character in text.chars() {
        if character.is_ascii_alphabetic() {
            cleaned_text.push(character.to_ascii_uppercase());
        }
    }

    cleaned_text
}

// Find repeated trigrams (3-letter sequences) and calculate distances between them
pub fn find_repeat_distances(text: &str) -> Vec<usize> {
    let mut trigram_map = HashMap::new();
    let mut distances_found = Vec::new();

    for i in 0..text.len().saturating_sub(2) {
        let trigram = &text[i..i + 3];
        trigram_map.entry(trigram).or_insert_with(Vec::new).push(i);
    }

    for positions in trigram_map.values() {
        if positions.len() > 1 {
            for j in 1..positions.len() {
                let distance = positions[j] - positions[j - 1];
                distances_found.push(distance);
            }
        }
    }

    distances_found
}

// Calculate the Greatest Common Divisor (GCD) of two numbers
pub fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

// Estimate likely key length based on repeating distances
pub fn estimate_key_length(distances: &[usize]) -> usize {
    let mut gcd_counts = HashMap::new();

    for i in 0..distances.len() {
        for j in i + 1..distances.len() {
            let common_divisor = gcd(distances[i], distances[j]);

            if common_divisor > 1 && common_divisor <= 40 {
                *gcd_counts.entry(common_divisor).or_insert(0) += 1;
            }
        }
    }

    // Sort and display possible key lengths
    let mut sorted_lengths: Vec<_> = gcd_counts.iter().collect();
    sorted_lengths.sort_by(|a, b| b.1.cmp(a.1));

    println!("\n📏 Possible key lengths:");
    for (length, count) in &sorted_lengths {
        println!("Length: {:>2}, Count: {}", length, count);
    }

    // Pick the most common length, or default to 3
    sorted_lengths.first().map(|(&len, _)| len).unwrap_or(3)
}

// Score how well a given Caesar shift fits English letter frequencies
pub fn chi_squared(text: &str, shift: usize) -> f64 {
    let mut letter_counts = [0; 26];

    for character in text.chars() {
        let index = ((character as u8 - b'A' + 26 - shift as u8) % 26) as usize;
        letter_counts[index] += 1;
    }

    let total_letters = text.len() as f64;
    let mut chi_score = 0.0;

    for i in 0..26 {
        let observed = letter_counts[i] as f64;
        let expected = ENGLISH_LETTER_FREQUENCIES[i] * total_letters / 100.0;

        // Avoid division by zero
        chi_score += (observed - expected).powi(2) / expected.max(0.01);
    }

    chi_score
}

// Try different Caesar shifts on each part of the ciphertext to figure out the key
pub fn recover_key(ciphertext: &str, key_length: usize) -> String {
    let mut key_result = String::new();

    for i in 0..key_length {
        // Grab every Nth character to analyze a single Caesar-encrypted slice
        let slice: String = ciphertext.chars().skip(i).step_by(key_length).collect();

        let mut best_shift = 0;
        let mut best_score = f64::MAX;

        for shift in 0..26 {
            let score = chi_squared(&slice, shift);

            if score < best_score {
                best_score = score;
                best_shift = shift;
            }
        }

        // Convert shift back to corresponding letter
        key_result.push((b'A' + best_shift as u8) as char);
    }

    key_result
}

// Decrypt the ciphertext using the Vigenère key
pub fn decrypt(ciphertext: &str, key: &str) -> String {
    let mut result = String::new();
    let key_bytes = key.as_bytes();
    let key_length = key.len();

    for (i, c) in ciphertext.bytes().enumerate() {
        let key_letter = key_bytes[i % key_length] - b'A';
        let decrypted_letter = ((26 + c - b'A' - key_letter) % 26) + b'A';
        result.push(decrypted_letter as char);
    }

    result
}

