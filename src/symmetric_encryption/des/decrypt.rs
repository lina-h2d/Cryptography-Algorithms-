use super::{constants, base};
fn pkcs5_unpad(blocks: &mut Vec<[u8; constants::BLOCK_SIZE]>) -> Vec<u8>{
    let mut rslt = Vec::new();
    let block = blocks.last().unwrap();
    let blocks_len = blocks.len();

    for i in 0..blocks_len {
        rslt.extend(blocks[i]);
    }

    // Early return if no padding
    if (block[7] != block[6]) && (block[7] != 1) {
        return rslt;
    }

    let padded_val = block[7] as usize;
    if padded_val > constants::BLOCK_SIZE {
        panic!("Padding '{}' larger than Block Size '{}'.", padded_val, constants::BLOCK_SIZE);
    }
    
    rslt[0..(blocks_len * constants::BLOCK_SIZE - padded_val)].to_vec()
}

pub fn decryptECB(_ciphertext: Vec<u8>, key: &[u8; constants::BLOCK_SIZE]) -> Vec<u8>  {
    let mut rslt = Vec::new();
    let ciphertext = _ciphertext.clone();
    let keys = base::generateKeys(key);

    for (_i, block) in ciphertext.chunks(constants::BLOCK_SIZE).enumerate() {
        let block_slice = <&[u8; constants::BLOCK_SIZE]>::try_from(block).unwrap();

        rslt.push(base::doBlock(block_slice, &keys, constants::operation::Decrypt));
    }
    let rslt = pkcs5_unpad(&mut rslt);

    rslt
}

pub fn decryptCBC(_ciphertext: Vec<u8>, _iv: &[u8; constants::BLOCK_SIZE], key: &[u8; constants::BLOCK_SIZE]) -> Vec<u8> {
    let mut rslt = Vec::new();
    let ciphertext = _ciphertext.clone();
    let mut iv = _iv.clone();
    let keys = base::generateKeys(key);

    for (_i, block) in ciphertext.chunks(constants::BLOCK_SIZE).enumerate() {
        let block_slice = <&[u8; constants::BLOCK_SIZE]>::try_from(block).unwrap();
        let mut decrypted_block = base::doBlock(block_slice, &keys, constants::operation::Decrypt);
        decrypted_block = base::xorIV(&decrypted_block, &iv);
        iv = block_slice.clone();

        rslt.push(decrypted_block);
    }
    let rslt = pkcs5_unpad(&mut rslt);

    rslt
}