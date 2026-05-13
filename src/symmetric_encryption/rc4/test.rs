#[cfg(test)]
mod tests {
    use super::*;
    use super::super::rc4::*;

    #[test]
    fn test_vector_key_plaintext() {
        let key = b"Key";
        let plaintext = b"Plaintext";
        let expected_hex = "BB F3 16 E8 D9 40 AF 0A D3";
        let ciphertext = rc4(key, plaintext);
        assert_eq!(to_hex(&ciphertext), expected_hex);
    }

    #[test]
    fn test_vector_wiki_pedia() {
        let key = b"Wiki";
        let plaintext = b"pedia";
        let expected_hex = "10 21 BF 04 20";
        let ciphertext = rc4(key, plaintext);
        assert_eq!(to_hex(&ciphertext), expected_hex);
    }

    #[test]
    fn test_vector_secret_attack() {
        let key = b"Secret";
        let plaintext = b"Attack at dawn";
        let expected_hex = "45 A0 1F 64 5F C3 5B 38 35 52 54 4B 9B F5";
        let ciphertext = rc4(key, plaintext);
        assert_eq!(to_hex(&ciphertext), expected_hex);
    }
}