use super::rc4::rc4;

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    rc4(key, plaintext)
}
