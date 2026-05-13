use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::exit;
use std::thread;
use num_bigint::BigUint;
use num_traits::Zero;
use crate::asymmetric_encryption::RSA::rsa_generate_key_pair;
use super::util::*;
use super::base::*;

pub fn chat_loop(stream: TcpStream, key: [u8; 16]) {
    print!("Generating RSA Key pair... ");          io::stdout().flush().unwrap();
    let (local_mod, local_pub, local_prv) = rsa_generate_key_pair(512, 5);
    let local_rsa = RSA_KEY {
        n: local_mod,
        e: local_pub,
        d: local_prv,
    };
    println!("Done.");

    // Get peer address once at start
    let peer_addr = stream.peer_addr().unwrap();
    let local_addr = stream.local_addr().unwrap();

    let mut input = String::new();

    print!("Exchanging RSA Credentials... ");       io::stdout().flush().unwrap();
    let mut recv_stream = stream.try_clone().expect("Failed to clone stream");
    let mut send_stream = stream.try_clone().expect("Failed to clone stream");

    // Send public key to peer
    write_biguint(&mut send_stream, &local_rsa.n).expect("Failed to send modulus");
    write_biguint(&mut send_stream, &local_rsa.e).expect("Failed to send public key");

    // Receive RSA Public key from peer
    let peer_mod = read_biguint(&mut recv_stream).expect("Failed to read peer's modulus");
    let peer_pub = read_biguint(&mut recv_stream).expect("Failed to read peer's public key");

    let peer_rsa = RSA_KEY {
        n: peer_mod,
        e: peer_pub,
        d: BigUint::zero()
    };
    println!("Done.");
    
    // TRY A SHARED OBJECT FILE SOLUTION, BETWEEN RECEIVER AND SENDER THREADS, NEED TO VERIFY COMPATIBILITY WITH WINDOWS, AS I ONLY HEARD OF SHARED OBJECT FILES IN LINUX
    
    // Basic RSA Logging
    println!("\n* Local RSA Credentials:");
    println!("\t- Modulus    : {}", local_rsa.n);
    println!("\t- Public Key : {}", local_rsa.e);
    println!("\t- Private Key: {}", local_rsa.d);

    println!("* Peer RSA Credentials:");
    println!("\t- Modulus   : {}", peer_rsa.n);
    println!("\t- Public Key: {}", peer_rsa.e);
    
    println!("\nYou can Exit By Typing '{}'.\n", EXIT_MESSAGE);

    // Spawn receiver thread
    thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        // Main Receiving and printing loop
        loop {
            match recv_stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    print!("\x1B[2K\r"); // Clear current line
                    let msg = Message::fromBytes(&buffer, &peer_rsa).expect("Invalid Message.");
                    
                    // FOR DEBUGGING PURPOSES
                    // println!("Text before Decrypting: {:?}", msg.Data);
                    // println!("Text  after Decrypting: {:?}", msg.getClearText(&key));

                    let cleartext = msg.getClearText(&key);
                    let cleartext = String::from_utf8_lossy(cleartext.as_slice());
                    
                    if cleartext.as_ref() == EXIT_MESSAGE {
                        print!("Received Exit Message From Peer, Shutting Down Connection... ");
                        io::stdout().flush().unwrap();
                        recv_stream.shutdown(Shutdown::Both).expect("Failed to shutdown stream");
                        println!("Done.");
                        exit(0);
                    }

                    println!("{}:{}> {}",
                           peer_addr.ip(), peer_addr.port(),
                           cleartext,
                    );
                    println!("{:?}", msg);
                    
                    print!("{}:{}> ", local_addr.ip(), local_addr.port());
                    io::stdout().flush().unwrap();
                    buffer = [0u8; 1024];
                },
                Ok(_) => break, // Connection closed
                Err(e) => {
                    eprintln!("\nConnection error: {}", e);
                    break;
                }
            }
        }
    });

    // Main sending loop
    loop {
        let mut c = [0u8; 1];

        print!("{}:{}> ", local_addr.ip(), local_addr.port());
        io::stdout().flush().unwrap();

        loop {
            match io::stdin().read_exact(&mut c) {
                Ok(_) => if c[0] as char != '\n' { input.push(c[0] as char); },
                Err(e) => {
                    eprintln!("Input char: {}", e);
                    break;
                }
            }
         
            if c[0] == 0x0A {       // '\n'
                if input.is_empty() { continue; }

                // input.push(0 as char); // For termination
                let message = Message::new(&input.clone().into_bytes(), &key, &local_rsa);

                if send_stream.write_all(message.clone().toBytes().as_slice()).is_err() {
                    eprintln!("Failed to send message");
                    break;
                }

                if input.as_str() == EXIT_MESSAGE {
                    print!("Received Exit Message, Shutting Down Connection... ");
                    io::stdout().flush().unwrap();
                    send_stream.shutdown(Shutdown::Both).expect("Failed to shutdown stream");
                    println!("Done.");
                    exit(0);
                }

                println!("{:?}", message);
                input.clear();
                break;
            }
        }
    }
}