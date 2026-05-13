use super::rc4::rc4;

pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    rc4(key, ciphertext)
}
