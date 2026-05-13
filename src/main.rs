#![allow(nonstandard_style)]
#![allow(dead_code)]

mod classical_ciphers;
mod menu;
mod symmetric_encryption;
mod asymmetric_encryption;
mod Hashing;
mod secureChannel;

const options: [&str; 6] = [
    "Ciphers",
    "Symmetric Encryption Systems",
    "Asymmetric Encryption Systems",
    "Secure Communication Channel",
    "Help",
    "Quit",
];

fn printMenu(){
    println!("PLease choose an option:");
    for i in 0..options.len(){ println!("{}- {} ", i + 1, options[i]); }
}

fn printHelp() {
    println!("Run the binary through `./cryptorust` or `cargo run`, and chose whatever options suite you from our interactive CLI.");
}

fn main() {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
    loop {
        let mut PATH = String::from("/");
        printMenu();
        let r = menu::getInput(PATH.clone(), 1, options.len());
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        match r {
            1 => classical_ciphers::menu::Menu(&mut PATH),
            2 => symmetric_encryption::menu::Menu(&mut PATH),
            3 => asymmetric_encryption::menu::Menu(&mut PATH),
            4 => secureChannel::menu::Menu(&mut PATH),
            5 => printHelp(),
            6 => {
                println!("Good Bye !! ");
                break;
            },
            _ => println!("This option isn't yet available"),
        }
    }
}