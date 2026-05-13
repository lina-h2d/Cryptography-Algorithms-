use std::io;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::str::FromStr;
use rand::random;
use super::establishment::*;
use super::base::PROTOCOL_PORT;
use super::chat::*;

const options: [&str; 3] = [
    "1- Host",
    "2- Connect",
    "3- Return"
];

fn printMenu(){
    println!("Please choose an option:");
    for i in 0..options.len(){
        println!("{}", options[i]);
    }
}

pub fn Menu(PATH: &mut String){
    const PREFIX: &str = "secure_channel/";

    PATH.push_str(PREFIX);
    // loop {
        printMenu();
        let r = super::getInput(PATH.clone(), 1, options.len());
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        match r {
            1 => Host(),
            2 => Connect(),
            _ => return
        };
    // }

    PATH.drain(PATH.len() - PREFIX.len()..);
    return;
}

pub fn Host() {
    let listener = TcpListener::bind(("0.0.0.0", PROTOCOL_PORT)).expect("Failed to bind port");
    print!("Server listening on  {}:{}...", listener.local_addr().unwrap().ip(), listener.local_addr().unwrap().port());
    io::stdout().flush().unwrap();  // Force flush
    
    // Generate a random AES key (16 bytes for AES-128)
    let aes_key = random::<[u8; 16]>();
    let mut peer = None;

    for stream in listener.incoming(){
        match stream {
            Ok(mut stream) => {
                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
                println!("New connection from {}:{}...", stream.peer_addr().unwrap().ip(), stream.peer_addr().unwrap().port());
                setupConnection_host(&mut stream, &aes_key);
                peer = Some(stream);
                break;
            }
            Err(e) => eprintln!("Error: {}", e)
        }
    };

    chat_loop(peer.expect("Lost Connection After it has been established."), aes_key);
}

fn Connect() {
    let mut addr = String::new();
    print!("Enter IPv4 Address: ");               io::stdout().flush().unwrap();
    io::stdin().read_line(&mut addr).expect("Failed to read plaintext");
    addr = addr.trim().to_string();

    let addr = Ipv4Addr::from_str(&addr).expect(format!("Invalid Address '{addr}'").as_str());
    let sock = SocketAddrV4::from_str(format!("{addr}:{PROTOCOL_PORT}").as_str())
        .expect(format!("Invalid socket address '{addr}'").as_str());

    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
    let aes_key;
    let peer;
    print!("Connecting to {}:{}... ", sock.ip(), sock.port());  io::stdout().flush().unwrap();  // Force flush
    match TcpStream::connect(sock) {
        Ok(mut stream) => {
            println!("Done.");
            aes_key = setupSession_connector(&mut stream);
            peer = stream;
        },
        Err(e) => panic!("\nError Connecting to {sock}: {e}")
    };

    chat_loop(peer, aes_key);
}