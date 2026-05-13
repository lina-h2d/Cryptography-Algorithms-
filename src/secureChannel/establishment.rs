use std::io;
use std::io::Write;
use std::net::TcpStream;
use num_bigint::BigUint;
use crate::asymmetric_encryption::ElGamal::{ElGamal_decrypt, ElGamal_encrypt, ElGamal_generate_keys};
use super::util::*;

pub fn setupSession_connector(stream: &mut TcpStream) -> [u8; 16] {
    print!("Generating ElGamal key pair... ");      io::stdout().flush().unwrap();  // Force flush
    let (pub_key, prv_key, p, g) = ElGamal_generate_keys(256, 10);
    println!("Done.");

    print!("Sending ElGamal Public Key... ");      io::stdout().flush().unwrap();
    // Send public parameters to client
    write_biguint(stream, &p).expect("Failed to send p");
    write_biguint(stream, &g).expect("Failed to send g");
    write_biguint(stream, &pub_key).expect("Failed to send public key");
    println!("Done.");

    print!("Receiving AES Key... ");              io::stdout().flush().unwrap();
    // Receive encrypted AES key from client
    let encrypted_aes = read_biguint(stream).expect("Failed to read ciphertext");
    let ephemeral_pk = read_biguint(stream).expect("Failed to read ephemeral_pk");

    // Decrypt the AES key
    let aes_key = ElGamal_decrypt(&encrypted_aes, &ephemeral_pk, &p, &prv_key);
    let aes_key: [u8; 16] = match aes_key.to_bytes_be().try_into() {
        Ok(k) => k,
        Err(t) => panic!("Key length must be 16 but got '{}'.", t.len()),
    };
    println!("Done.");

    println!("Established session with AES key: {:?}", aes_key);
    aes_key
}

pub fn setupConnection_host(stream: &mut TcpStream, _aes_key: &[u8; 16]) {

    print!("Receiving Peer's ElGamal Public Key... ");       io::stdout().flush().unwrap();
    // Receive ElGamal parameters from server
    let p = read_biguint(stream).expect("Failed to read p");
    let g = read_biguint(stream).expect("Failed to read g");
    let pub_key = read_biguint(stream).expect("Failed to read client's public key");
    println!("Done.");

    let aes_key = BigUint::from_bytes_be(_aes_key);

    print!("Sending AES Key... ");                          io::stdout().flush().unwrap();
    // Encrypt the AES key with client's public key
    let (ciphertext, ephemeral_pk) = ElGamal_encrypt(&aes_key, &pub_key, &p, &g);
    
    // Send encrypted AES key to server
    write_biguint(stream, &ciphertext).expect("Failed to send ciphertext");
    // println!("Sent ciphertext: {:?}", ciphertext.to_bytes_be());
    write_biguint(stream, &ephemeral_pk).expect("Failed to send ephemeral_pk");
    // println!("Sent ephemeral_pk: {:?}", ephemeral_pk.to_bytes_be());
    println!("Done.");

    println!("Established session with AES key: {:?}", _aes_key);
}