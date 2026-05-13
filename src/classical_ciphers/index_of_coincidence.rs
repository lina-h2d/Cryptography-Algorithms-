use crate::classical_ciphers::frequency_analysis::frequency_counter;

pub fn index_of_coincidence_counter(ciphertext: &str) -> f64 {
    let filtered_text: String = ciphertext.chars()
        .filter(|c| c.is_alphabetic())
        .collect::<String>()
        .to_ascii_lowercase();

    let freq = frequency_counter(&filtered_text);
    let ciphertext_len = filtered_text.len();
    if ciphertext_len < 2 {
        return  0.0
    };
    let mut index_of_coincidence: f64 = 0.0;
    for &count in freq.values() {
        if count > 1 {
            index_of_coincidence += (count as f64) * ((count - 1) as f64);
        }
    }
    index_of_coincidence / ((ciphertext_len as f64) * ((ciphertext_len - 1) as f64))
}
