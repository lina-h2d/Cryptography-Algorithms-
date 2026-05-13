use super::constants;

// 'pos' from 1 .. 64
fn getBit_64(num: u64, pos: usize) -> u64 {
    (num & (1 << (64 - pos))) >> (64 - pos)
}

fn getBit_56(num: u64, pos: usize) -> u64 {
    (num & (1 << (56 - pos))) >> (56 - pos)
}

fn getBit_32(num: u32, pos: usize) -> u32 {
    (num & (1 << (32 - pos))) >> (32 - pos)
}

pub fn xorIV(data: &[u8; constants::BLOCK_SIZE], iv: &[u8; constants::BLOCK_SIZE]) -> [u8; constants::BLOCK_SIZE] {
    let mut rslt = [0u8; constants::BLOCK_SIZE];
    for i in 0..rslt.len() {
        rslt[i] = data[i] ^ iv[i];
    }

    rslt
}

// Arrays' elements must be of value 1..64; not 0..63
fn permute_64(input: u64, arr: &[usize; 64]) -> u64 {
    let mut rslt: u64 = 0;

    for i in 00..64 { rslt |= getBit_64(input, arr[i]) << (63 - i); }

    rslt
}

fn permute_56(input: u64, arr: &[usize; 56]) -> u64 {
    let mut rslt: u64 = 0;

    for i in 00..56 { rslt |= getBit_64(input, arr[i]) << (55 - i); }

    rslt & 0xFFFFFFFFFFFFFF
}

fn PC2Permutation(input: u64, arr: &[usize; 48]) -> u64 {
    let mut rslt: u64 = 0;

    for i in 00..48 { rslt |= getBit_56(input, arr[i]) << (47 - i); }

    rslt & 0xFFFF_FFFF_FFFF
}

fn permute_32(input: u32, arr: &[usize; 32]) -> u32 {
    let mut rslt: u32 = 0;

    for i in 00..32 { rslt |= getBit_32(input, arr[i]) << (31 - i); }

    rslt
}

fn initialPermutation(input: u64) -> u64 { permute_64(input, &constants::IP) }

fn expansion(input: u32) -> u64 {
    let mut rslt: u64 = 0;

    for i in 0..constants::expansion_table.len() {
        rslt |= (getBit_32(input, constants::expansion_table[i]) as u64) << (47 - i);
    }

    rslt
}

fn XOR_48(input: u64, key: u64) -> u64 {
    (input ^ key) & 0xFFFF_FFFF_FFFF
}

fn SBox(input: u64) -> u32 {
    let mut rslt = String::new();
    let str_num = format!("{:048b}", input);

    for i in 0..8 {
        let slice = &str_num.as_str()[i * 6..i * 6 + 6];
        let slice = u8::from_str_radix(slice, 2).unwrap();
        let slice_rslt = format!("{:04b}", SBox_Transform(slice, &constants::S_BOXES[i]));
        rslt.push_str(slice_rslt.as_str());

    }
    u32::from_str_radix(rslt.as_str(), 2).unwrap()
}

fn SBox_Transform(input: u8, table: &[[usize; 16]; 4]) -> u8 {
    let row = (((input & 0x20) >> 4) | input & 0x01) as usize;  // 1st & 6th bits
    let column = ((input & 0x1E) >> 1) as usize;                // Remaining 4 bits

    (table[row][column] & 0x0F) as u8                                 // & with 4 bits for safety
}

fn PBox_Permutation(input: u32) -> u32 { permute_32(input, &constants::P_BOX) }

fn FinalPermutation(input: u64) -> u64 { permute_64(input, &constants::FINAL_PERMUTATION) }

fn reduceKey(input: u64) -> u64 { permute_56(input, &constants::PC1) }

fn Rotate_28(data: u32, count: usize) -> u32 {
    let count = count % 28;
    ((data << count) | (data >> (28 - count))) & 0xF_FFF_FFF
}

fn permute_subKey(input: u64) -> u64 { PC2Permutation(input, &constants::PC2) }

pub fn generateKeys(_key: &[u8; 8]) -> [u64; 16] {
    let mut rslt: [u64; 16] = [0; 16];
    let mut key = u64::from_be_bytes(*_key);
    key = reduceKey(key);
    
    let mut L_Half: u32 = (key >> 28) as u32;
    let mut R_Half: u32 = (key & 0xFFFFFFF) as u32;

    for i in 0..16 {
        L_Half = Rotate_28(L_Half, constants::KEY_ROTATIONS[i]);
        R_Half = Rotate_28(R_Half, constants::KEY_ROTATIONS[i]);

        key = ((L_Half as u64) << 28) | R_Half as u64;
        rslt[i] = permute_subKey(key);
    }
    rslt
}

fn doRound(LPT: &mut u32, RPT: &mut u32, RPT_0: &mut u32, key: u64) {
    *RPT_0 = *RPT;
    let mut eRPT = expansion(*RPT);

    eRPT = XOR_48(eRPT, key);
    *RPT = SBox(eRPT);
    *RPT = PBox_Permutation(*RPT);

    // Swap
    *RPT ^= *LPT;
    *LPT = *RPT_0;
}

pub fn doBlock(block: &[u8; constants::BLOCK_SIZE], keys: &[u64; constants::ITERATION_NB], op: constants::operation) -> [u8; constants::BLOCK_SIZE] {
    let mut data = u64::from_be_bytes(*block);
    data = initialPermutation(data);

    let mut LPT: u32 = (data >> 32) as u32;
    let mut RPT_0: u32 = (data & 0xFFFFFFFF) as u32;    // Original RPT, goes Into LPT at end of iteration
    let mut RPT: u32 = RPT_0;                             // The RPT that will be modified through the iteration

    match op {
        constants::operation::Encrypt =>
            for iteration in 0..constants::ITERATION_NB {
                doRound(&mut LPT, &mut RPT, &mut RPT_0, keys[iteration]);
            }
        constants::operation::Decrypt =>
            for iteration in (0..constants::ITERATION_NB).rev() {
                doRound(&mut LPT, &mut RPT, &mut RPT_0, keys[iteration]);
            }
    }

    // Group the halves, I really don't know why RPT and RPT_0, maybe because I also swapped at last iteration ? anyway it's correct and verified.
    data = ((RPT as u64) << 32) | RPT_0 as u64;
    data = FinalPermutation(data);

    data.to_be_bytes()
}