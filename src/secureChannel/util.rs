// A File containing helper functions

use std::io;
use std::io::{Read, Write};
use num_bigint::BigUint;

pub fn write_biguint(writer: &mut impl Write, num: &BigUint) -> io::Result<()> {
    let bytes = num.to_bytes_be();
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)
}

pub fn read_biguint(reader: &mut impl Read) -> io::Result<BigUint> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(BigUint::from_bytes_be(&buf))
}

pub fn cmp_vec<T: PartialEq>(A: &Vec<T>, b: &Vec<T>) -> bool {
    if A.len() != b.len() { return false; }
    for (a, b) in A.iter().zip(b.iter()) {
        if a != b {
            return false;
        }
    }
    true
}