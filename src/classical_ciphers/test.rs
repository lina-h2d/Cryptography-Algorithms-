#[cfg(test)]
mod tests {
    use crate::classical_ciphers::affine_cipher::{decrypt_affine, encrypt_affine};
    use crate::classical_ciphers::caesar::{decrypt_caesar, encrypt_caesar};
    use crate::classical_ciphers::frequency_analysis::{decrypt_using_freq_analysis, frequency_counter};
    use crate::classical_ciphers::one_time_pad::{decrypt_otp, encrypt_otp};
    use crate::classical_ciphers::random_substitution::{decrypt_random_substitution, encrypt_random_substitution, generate_random_substitution_key};
    use crate::classical_ciphers::vigenere::{decrypt_vigenere, encrypt_vigenere};
    use crate::classical_ciphers::playfair::{decrypt_playfair, encrypt_playfair};
    use crate::classical_ciphers::index_of_coincidence::index_of_coincidence_counter;
    use crate::classical_ciphers::rail_fence;
    use crate::classical_ciphers::Kasiski_Test::*;

    #[test]
    fn test_caesar_cipher() {
        assert_eq!(encrypt_caesar("HELLO", 3), "KHOOR");
        assert_eq!(decrypt_caesar("KHOOR", 3), "HELLO");
    }
    #[test]
    fn test_vigenere_cipher() {
        assert_eq!(encrypt_vigenere("HELLO WORLD", "KEY"), "RIJVS UYVJN", "Encryption failed!");
        assert_eq!(decrypt_vigenere("RIJVS UYVJN", "KEY"), "HELLO WORLD", "Encryption failed!");
    }
    #[test]
    fn test_otp_cipher() {
        let plaintext = "HELLO WORLD";
        let (ciphertext, key) = encrypt_otp(plaintext);
        let decrypted = decrypt_otp(&ciphertext, &key);

        assert_eq!(decrypted, plaintext, "Decryption should return the original plaintext");
        assert_ne!(ciphertext, plaintext, "Ciphertext should not be the same as plaintext");
        assert_ne!(ciphertext, key, "Ciphertext should not be the same as the key");
    }
    #[test]
    fn test_random_substitution_cipher() {
        let key = generate_random_substitution_key();
        let plaintext = "HELLO WORLD";
        assert_eq!(decrypt_random_substitution(&encrypt_random_substitution(plaintext, &key), &key), plaintext);
    }
    #[test]
    fn test_frequency_analysis() {
        let ciphertext = "HELLO WORLD";
        let freq_map = frequency_counter(ciphertext);

        assert_eq!(freq_map[&'H'], 1);
        assert_eq!(freq_map[&'E'], 1);
        assert_eq!(freq_map[&'L'], 3);
        assert_eq!(freq_map[&'O'], 2);
        assert_eq!(freq_map[&'W'], 1);
        assert_eq!(freq_map[&'R'], 1);
        assert_eq!(freq_map[&'D'], 1);

        assert_eq!(freq_map[&'X'], 0);
        assert_eq!(freq_map[&'Z'], 0);
    }
    #[test]
    fn test_playfair_cipher() {
       assert_eq!(encrypt_playfair("cryptographie", "ghedwa"), "MXUSZTEPKUWBCE");
       assert_eq!(decrypt_playfair("MXUSZTEPKUWBCE", "ghedwa"), "CRYPTOGRAPHIEX");
    }

    #[test]
    fn test_index_of_coincidence_counter() {
        let ciphertext = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";

        // Calculate the IoC
        let ioc = index_of_coincidence_counter(ciphertext);

        let expected_ioc = 52.0 / (52.0 * 51.0);

        assert!((ioc - expected_ioc).abs() < 1e-10, "Index of Coincidence calculation is incorrect");
    }

    #[test]
    fn test_decrypt_using_freq_analysis() {
        let expected_plaintext  = "This is a secret message that is encrypted using a caesar cipher. It is not really secret, but it is a fun example for testing your code. If you can decrypt this message, you are on the right path to decrypting real messages!";
        let ciphertext  = encrypt_caesar(expected_plaintext, 4);

        let possible_decryptions = decrypt_using_freq_analysis(&*ciphertext);

        let mut found = false;
        for decryption in possible_decryptions {
            if decryption.eq_ignore_ascii_case(expected_plaintext) {
                found = true;
                break;
            }
        }
        assert!(found, "The expected plaintext was not found in the possible decryptions.");
    }
    #[test]
    fn test_affine_cipher(){
        let plaintext = "INFO ING 3 SEC";
        let a: u8 =  5;
        let b : u8 = 6;
        assert_eq!(plaintext, decrypt_affine(&*encrypt_affine(plaintext, a, b), a, b));
    }

    #[test]
    fn test_rail_fence_cipher() {
        // Encryption
        assert_eq!(rail_fence::encrypt("HELLO", 2), "HLOEL");
        assert_eq!(rail_fence::encrypt("HELLOWORLD", 3), "HOLELWRDLO");
        assert_eq!(rail_fence::encrypt("RAILFENCE", 4), "RNAECIFEL");

        // Decryption
        assert_eq!(rail_fence::decrypt("IFIGNON", 2), "INFOING");
        assert_eq!(rail_fence::decrypt("HOELMMLO", 3), "HELLOMOM");
        assert_eq!(rail_fence::decrypt("REACCINIRLEPEFH", 5), "RAILFENCECIPHER");
    }

    #[test]
    fn test_clean_input() {
        let input = "Hello, World! 123";
        let expected = "HELLOWORLD";
        assert_eq!(clean_input(input), expected);
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(48, 18), 6);
        assert_eq!(gcd(100, 10), 10);
        assert_eq!(gcd(17, 5), 1);
    }

    #[test]
    fn test_find_repeat_distances() {
        let input = "ABCDABCDABCD";
        let cleaned = clean_input(input);
        let distances = find_repeat_distances(&cleaned);
        // We expect repeated trigrams "ABC", "BCD", "CDA", etc.
        assert!(distances.contains(&4)); // Distance between first and second "ABC"
    }

    #[test]
    fn test_chi_squared_score_lower_is_better() {
        let input = "THISISATESTTEXT";
        let cleaned = clean_input(input);
        let score_shift_0 = chi_squared(&cleaned, 0);
        let score_shift_13 = chi_squared(&cleaned, 13);
        // Just check that the function returns a valid score
        assert!(score_shift_0 >= 0.0);
        assert!(score_shift_13 >= 0.0);
    }

    #[test]
    fn test_recover_key_simple() {
        // Vigenère encrypted "ATTACKATDAWN" with key "LEMON" => "LXFOPVEFRNHR"
        let ciphertext = "WAINKMYTWWLBPDSMFWXMIHLKLTWIQAPSHOQIFTFYDAAEQNFZFCWUOZPNTIUKPPOLOINRMJWWRROJKQPLSMVQRNONXZPSBOPMCIEOHABUWMRVEGSHHZPEGUOITDSXHKWEGJUQGESMSMCMSNWMYTRYYMCITCHZWIRYQBTTSXHTPXDYGQEEILFMWAUUUIYTWNTCPLSGHADAUYSZZVWYQBMISHGMWAGIXZNERYFTLRSYHBYADUVMEETUOATFWYGIYSZYFIORSXHAEROHVINTWIQAPNZCJVPCSNWMLSGOUIYCSYVBQOBXDUPNHUOMAOILHBLBZCUTLCCHIQLNQYHVERSFHAAAFNLMDIAJOQBUSYV";
        let cleaned = clean_input(ciphertext);
        let recovered = recover_key(&cleaned, 6); // We know key length is 5
        assert_eq!(recovered, "LAOUDI");
    }

    #[test]
    fn test_vigenere_decrypt() {
        let ciphertext = "
            WAINKMYTWWLBPDSMFWXMIHLKLTWIQAPSHOQIFTFYDAAEQNFZFCWUOZPNTIUKPPOLOINRMJWWRROJKQPLSMVQRNONXZPSBOPMCIEOHABUWMRVEGSHHZPEGUOITDSXHKWEGJUQGESMSMCMSNWMYTRYYMCITCHZWIRYQBTTSXHTPXDYGQEEILFMWAUUUIYTWNTCPLSGHADAUYSZZVWYQBMISHGMWAGIXZNERYFTLRSYHBYADUVMEETUOATFWYGIYSZYFIORSXHAEROHVINTWIQAPNZCJVPCSNWMLSGOUIYCSYVBQOBXDUPNHUOMAOILHBLBZCUTLCCHIQLNQYHVERSFHAAAFNLMDIAJOQBUSYV
        ";

        let clean_text = clean_input(ciphertext);
        let distances = find_repeat_distances(&clean_text);
        let key_len = estimate_key_length(&distances);
        let key = recover_key(&clean_text, key_len);
        let message = decrypt(&clean_text, &key);

        let expected_key_len = 6;
        let expected_key = "LAOUDI";
        let expected_message = "LAUTHENTICITEDESCOMMUNICATIONSESTUNAUTREASPECTCRUCIALRENFORCEPARLACRYPTOGRAPHIELESSIGNATURESNUMERIQUESQUISONTGENEREESALAIDEDECLESPRIVEESPERMETTENTDEVERIFIERLIDENTITEDELEXPEDITEURCELAGARANTITQUELEMESSAGEPROVIENTBIENDELASOURCEDECLAREEETNAPASETEFALSIFIEDANSLECADREDESTRANSACTIONSENLIGNECETTEASSURANCEESTFONDAMENTALEPOURETABLIRLACONFIANCEENTRELESPARTIESIMPLIQUEES";

        assert_eq!(key_len, expected_key_len, "Key length mismatch");
        assert_eq!(key, expected_key, "Recovered key mismatch");
        assert_eq!(message, expected_message, "Decrypted message mismatch");
    }

}