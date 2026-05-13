#[cfg(test)]
mod tests {
    use crate::symmetric_encryption::des::constants::*;
    use crate::symmetric_encryption::des::base::*;

    // Test vectors from official NIST documentation
    const ZERO_KEY: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    const WEAK_KEY1: [u8; 8] = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01]; // E001E001F101F101
    const WEAK_KEY2: [u8; 8] = [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE]; // FE1FFE1FFEFEEFEE
    const COMMON_KEY: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]; // A realistic key

    // Expected PC-1 output for ZERO_KEY
    const ZERO_KEY_PC1: u64 = 0x0; // After PC-1, all zeros remain zeros

    // Expected first and last subkeys for verification
    const EXPECTED_SUBKEYS_ZERO: [u64; 2] = [
        0x000000000000, // First subkey (K1)
        0x000000000000  // Last subkey (K16)
    ];

    const EXPECTED_SUBKEYS_COMMON: [u64; 2] = [
        0x194CD072DE8C, // First subkey (K1) for COMMON_KEY
        0x6C2DC5831551  // Last subkey (K16) for COMMON_KEY
    ];
}
