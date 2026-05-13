use crate::symmetric_encryption::aes::aes_utils::{add_blocks, gal_mul, SBOX, key_expansion, pad_pkcs7};
pub fn sub_bytes(state: &mut [u8 ; 16]){
        for byte in state.iter_mut(){
        *byte = SBOX[*byte as usize];
        }
}
pub fn shift_rows(state: &mut [u8; 16]) {
    let mut temp = [0u8; 16];
    temp.copy_from_slice(state);

    // column 0
    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];

    // column 1
    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];

    // column 2
    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];

    // column 3
    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}

pub fn mix_columns(state: &mut [u8; 16]) {
    let temp = *state;

    // column 0
    state[0] = gal_mul(temp[0], 0x02) ^ gal_mul(temp[1], 0x03) ^ temp[2] ^ temp[3];
    state[1] = temp[0] ^ gal_mul(temp[1], 0x02) ^ gal_mul(temp[2], 0x03) ^ temp[3];
    state[2] = temp[0] ^ temp[1] ^ gal_mul(temp[2], 0x02) ^ gal_mul(temp[3],0x03);
    state[3] = gal_mul(temp[0], 0x03) ^ temp[1] ^ temp[2] ^ gal_mul(temp[3],0x02);

    // column 1
    state[4] = gal_mul(temp[4], 0x02) ^ gal_mul(temp[5], 0x03) ^ temp[6] ^ temp[7];
    state[5] = temp[4] ^ gal_mul(temp[5], 0x02) ^ gal_mul(temp[6], 0x03) ^ temp[7];
    state[6] = temp[4] ^ temp[5] ^ gal_mul(temp[6], 0x02) ^ gal_mul(temp[7],0x03);
    state[7] = gal_mul(temp[4], 0x03) ^ temp[5] ^ temp[6] ^ gal_mul(temp[7],0x02);

    // column 2
    state[8] = gal_mul(temp[8], 0x02) ^ gal_mul(temp[9], 0x03) ^ temp[10] ^ temp[11];
    state[9] = temp[8] ^ gal_mul(temp[9], 0x02) ^ gal_mul(temp[10], 0x03) ^ temp[11];
    state[10] = temp[8] ^ temp[9] ^ gal_mul(temp[10], 0x02) ^ gal_mul(temp[11],0x03);
    state[11] = gal_mul(temp[8], 0x03) ^ temp[9] ^ temp[10] ^ gal_mul(temp[11],0x02);


    // column 3
    state[12] = gal_mul(temp[12], 0x02) ^ gal_mul(temp[13], 0x03) ^ temp[14] ^ temp[15];
    state[13] = temp[12] ^ gal_mul(temp[13], 0x02) ^ gal_mul(temp[14], 0x03) ^ temp[15];
    state[14] = temp[12] ^ temp[13] ^ gal_mul(temp[14], 0x02) ^ gal_mul(temp[15],0x03);
    state[15] = gal_mul(temp[12], 0x03) ^ temp[13] ^ temp[14] ^ gal_mul(temp[15],0x02);
}




// Encrypts a single block of 16 bytes
pub fn encrypt_block(input: &[u8;16], output: &mut[u8; 16], key: &[u8; 16]){
    let mut state = *input;
    let mut expanded_key = [0u8; 176];
    key_expansion(key, &mut expanded_key);
    add_blocks(&mut state, &expanded_key[0..16]);

    for round in 1..10{
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);

        // add round key
        add_blocks(&mut state, &expanded_key[round * 16..(round+1)*16]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_blocks(&mut state, &expanded_key[160..176]);

    output.copy_from_slice(&state);
}
pub fn encrypt_ecb(plaintext: Vec<u8>, key: &[u8; 16]) -> Vec<u8> {
    let block_size: usize = 16;
    let padded_plaintext = pad_pkcs7(&plaintext, block_size);
    let number_of_blocks = padded_plaintext.len() / block_size;

    let mut output = vec![0u8; number_of_blocks * block_size];

    for (i, block) in padded_plaintext.chunks(block_size).enumerate() {
        let block_slice = <&[u8; 16]>::try_from(block).unwrap();
        let mut encrypted_block = [0u8; 16];

        encrypt_block(block_slice, &mut encrypted_block, key);

        output[block_size * i..block_size * (i + 1)].copy_from_slice(&encrypted_block);
    }

    output
}

pub fn encrypt_cbc(plaintext: &Vec<u8>, iv : &[u8; 16], key: &[u8; 16]) -> Vec<u8> {
    let block_size: usize = 16;
    let padded_plaintext = pad_pkcs7(plaintext, block_size);
    let mut ciphertext : Vec<u8> = Vec::new();
    let mut last_block = *iv;
    let num_blocks = padded_plaintext.len() / block_size;
    for block_index in 0..num_blocks {
        let mut block = [0u8; 16];
        for a in 0..16{
            block[a] = padded_plaintext[block_index * block_size + a];
        }
        add_blocks(&mut block, &last_block);
        encrypt_block(&block.clone(), &mut block, &key);
        last_block = block;
        for b in block{
            ciphertext.push(b);
        }
    }
  ciphertext
}
