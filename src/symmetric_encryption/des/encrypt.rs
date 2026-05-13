use super::{constants, base};
fn pkcs5_pad(data: &mut Vec<u8>) -> &mut Vec<u8> {
    let pad_len = constants::BLOCK_SIZE - (data.len() % constants::BLOCK_SIZE);
    data.extend(vec![pad_len as u8; pad_len]);
    data
}

pub fn encryptECB(_plaintext: Vec<u8>, key: &[u8; constants::BLOCK_SIZE]) -> Vec<u8>  {
    let mut rslt = Vec::new();
    let mut plaintext = _plaintext.clone();
    pkcs5_pad(&mut plaintext);
    let keys = base::generateKeys(key);

    for (_i, block) in plaintext.chunks(constants::BLOCK_SIZE).enumerate() {
        let block_slice = <&[u8; constants::BLOCK_SIZE]>::try_from(block).unwrap();

        rslt.extend(base::doBlock(&block_slice, &keys, constants::operation::Encrypt));
    }

    rslt
}

pub fn encryptCBC(_plaintext: Vec<u8>, _iv: &[u8; constants::BLOCK_SIZE], key: &[u8; constants::BLOCK_SIZE]) -> Vec<u8> {
    let mut rslt = Vec::new();
    let mut plaintext = _plaintext.clone();
    pkcs5_pad(&mut plaintext);

    let keys = base::generateKeys(key);
    let mut iv = _iv.clone();
    
    for block in plaintext.chunks(constants::BLOCK_SIZE) {
        let block_slice = <&[u8; constants::BLOCK_SIZE]>::try_from(block).unwrap();
        let mut encrypted_block = base::xorIV(&block_slice, &iv);
        encrypted_block = base::doBlock(&encrypted_block, &keys, constants::operation::Encrypt);

        iv = encrypted_block.clone();
        rslt.extend(encrypted_block);
    }

    rslt
}