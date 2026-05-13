use crate::symmetric_encryption::aes::aes_utils::{add_blocks, gal_mul, INV_SBOX, key_expansion, remove_pad_pkcs7};

pub fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut(){
        *byte = INV_SBOX[*byte as usize];
    }
}
pub fn inv_shift_rows(state: &mut [u8; 16]) {
    let mut temp = [0u8; 16];
    temp.copy_from_slice(state);
    // no shifts
    state[0] = temp[0];
    state[4] = temp[4];
    state[8] = temp[8];
    state[12] = temp[12];

    // 1 shift to the right
    state[1]  = temp[13];
    state[5]  = temp[1];
    state[9]  = temp[5];
    state[13] = temp[9];

    // 2 shifts to the right
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];

    // 3 shifts to the right
    state[3] = temp[7];
    state[7] = temp[11];
    state[11] = temp[15];
    state[15] = temp[3];

}
pub fn inv_mix_columns(state: &mut [u8; 16]) {
    let temp = *state;

    // column 1
    state[0] = gal_mul(temp[0], 0xE) ^ gal_mul(temp[1], 0xB) ^ gal_mul(temp[2], 0xD) ^ gal_mul(temp[3], 0x9);
    state[1] = gal_mul(temp[0], 0x9) ^ gal_mul(temp[1], 0xE) ^ gal_mul(temp[2], 0xB) ^ gal_mul(temp[3], 0xD);
    state[2] = gal_mul(temp[0], 0xD) ^ gal_mul(temp[1], 0x9) ^ gal_mul(temp[2], 0xE) ^ gal_mul(temp[3], 0xB);
    state[3] = gal_mul(temp[0], 0xB) ^ gal_mul(temp[1], 0xd) ^ gal_mul(temp[2], 0x9) ^ gal_mul(temp[3], 0xe);

    // column 2
    state[4] = gal_mul(temp[4], 0xE) ^ gal_mul(temp[5], 0xB) ^ gal_mul(temp[6], 0xD) ^ gal_mul(temp[7], 0x09);
    state[5] = gal_mul(temp[4], 0x09) ^ gal_mul(temp[5], 0xE) ^ gal_mul(temp[6], 0xB) ^ gal_mul(temp[7], 0xD);
    state[6] = gal_mul(temp[4], 0xD) ^ gal_mul(temp[5], 0x9) ^ gal_mul(temp[6], 0xE) ^ gal_mul(temp[7], 0xB);
    state[7] = gal_mul(temp[4], 0xB) ^ gal_mul(temp[5], 0xD) ^ gal_mul(temp[6], 0x09) ^ gal_mul(temp[7], 0xE);
    // column 3
    state[8] = gal_mul(temp[8], 0xE) ^ gal_mul(temp[9], 0xB) ^ gal_mul(temp[10], 0xD) ^ gal_mul(temp[11], 0x09);
    state[9] = gal_mul(temp[8], 0x09) ^ gal_mul(temp[9], 0xE) ^ gal_mul(temp[10], 0xB) ^ gal_mul(temp[11], 0xD);
    state[10] = gal_mul(temp[8], 0xD) ^ gal_mul(temp[9], 0x09) ^ gal_mul(temp[10], 0xE) ^ gal_mul(temp[11], 0xB);
    state[11] = gal_mul(temp[8], 0xB) ^ gal_mul(temp[9], 0xD) ^ gal_mul(temp[10], 0x9) ^ gal_mul(temp[11], 0xE);

    // // column 4
    state[12] = gal_mul(temp[12], 0xE) ^ gal_mul(temp[13], 0xB) ^ gal_mul(temp[14], 0xD) ^ gal_mul(temp[15], 0x09);
    state[13] = gal_mul(temp[12], 0x09) ^ gal_mul(temp[13], 0xE) ^ gal_mul(temp[14], 0xB) ^ gal_mul(temp[15], 0x0D);
    state[14] = gal_mul(temp[12], 0xD) ^ gal_mul(temp[13], 0x09) ^ gal_mul(temp[14], 0xE) ^ gal_mul(temp[15], 0x0B);
    state[15] = gal_mul(temp[12], 0xB) ^ gal_mul(temp[13], 0xD) ^ gal_mul(temp[14], 0x09) ^ gal_mul(temp[15], 0x0E);

}

pub fn decrypt_cbc(ciphertext: Vec<u8>, iv : &[u8; 16], key: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    let block_size: usize = 16;
    if ciphertext.len() < 16 {
        return Err("ciphertext is too short");
    }
    let num_blocks = ciphertext.len() / 16;
    let mut last = iv.clone();
    let mut plaintext = vec![];

    for block_index in 0..num_blocks {
        let mut block: [u8; 16] = [0; 16];
        for a in 0..16{
            block[a] = ciphertext[block_index * 16 + a];
        }
        let xor = last;
        last = block;
        decrypt_block(&block.clone(), &mut block, &key);
        add_blocks(&mut block, &xor);
        for b in block{
            plaintext.push(b);
        }
    }
    // Ok(plaintext)
    Ok(remove_pad_pkcs7(&mut plaintext, block_size).expect("Failed to remove pad pkcs7"))

}

pub fn decrypt_ecb(ciphertext: &Vec<u8>, key: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    let block_size: usize = 16;
    if ciphertext.len() % block_size != 0 {
        return Err("Wrong length of ciphertext");
    }
    let number_of_blocks = ciphertext.len() / block_size;

    let mut output = vec![0u8; number_of_blocks * block_size];

    for (i, block) in ciphertext.chunks(block_size).enumerate() {
        let block_slice = <&[u8; 16]>::try_from(block).unwrap();
        let mut decrypted_block = [0u8; 16];

        decrypt_block(block_slice, &mut decrypted_block, key);

        output[block_size * i..block_size * (i + 1)].copy_from_slice(&decrypted_block);
    }
    Ok(remove_pad_pkcs7(&mut output, block_size).expect("Failed to remove pad pkcs7"))
}

pub fn decrypt_block(input: &[u8; 16], output: &mut [u8; 16], key: &[u8; 16]) {
    let mut state = *input;
    let mut expanded_key = [0u8; 176];
    key_expansion(key, &mut expanded_key);

    add_blocks(&mut state, &expanded_key[160..176]);

    for round in (1..10).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_blocks(&mut state, &expanded_key[round * 16..(round + 1) * 16]);
        inv_mix_columns(&mut state);
    }

    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_blocks(&mut state, &expanded_key[0..16]);

    output.copy_from_slice(&state);
}