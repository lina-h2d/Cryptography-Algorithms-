#![allow(nonstandard_style)]
use std::io;
use std::io::Write;
use num::Integer;

pub fn printGenericMenu(){
    println!("What do you want to do?");
    println!("1- Encrypt");
    println!("2- Decrypt");
    println!("3- Return");
}

pub fn getGenericOption(PATH: String) -> usize {
    printGenericMenu();
    let r = getInput(PATH, 1, 3);
    println!();
    r
}

pub fn parseHexBytes(buf: String) -> Vec<u8> {
    let mut rslt = Vec::new();
    let mut buffer: String;
    if buf.len() % 2 == 1 {
        buffer = String::from("0");
        buffer.push_str(buf.as_str().trim());
    }
    else { buffer = buf.clone(); }
    buffer = buffer.trim().to_string();

    for i in (0..buffer.len() - 1).step_by(2) {
        let numStr = &buf[i..i+2];
        rslt.push(
            u8::from_str_radix(numStr, 16)
                .expect(format!("Invalid hex sequence '{}'.", numStr).as_str())
        );
    }

    rslt
}

pub fn outputBytes(buf: Vec<u8>) {
    if buf.len().is_even() {
        for i in (0..buf.len() - 1).step_by(2) { print!("{:02x}{:02x} ", buf[i], buf[i+1]);/* printing in big endian order, swap endianness to verify with openssl command */}
    }
    else {
        for i in (0..buf.len() - 2).step_by(2) {
            print!("{:02x}{:02x} ", buf[i], buf[i+1]);
        }
        print!("{:02x} ", buf[buf.len() - 1]);
    }
    println!();
}

pub fn getInput(PATH: String, minVal: usize, maxVal: usize) -> usize {
    loop {
        let mut input: String = String::new();
        print!("{PATH}> ");        io::stdout().flush().unwrap();
        if io::stdin().read_line(&mut input).unwrap() == 1usize { continue; }
        match input.trim().parse::<usize>() {
            Ok(t) => {
                if t < minVal || t > maxVal { println!("Invalid Choice."); continue; }
                return t;
            },
            Err(_) => { println!("Invalid Input."); continue; }
        }
    }
}
