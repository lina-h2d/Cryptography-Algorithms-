pub(crate) use super::{parseHexBytes, outputBytes};

const RETURN_STATUS: usize = 0;

const options: [&str; 4] = [
    "1- AES",
    "2- DES",
    "3- RC4",
    "4- Return"
];

pub(crate) fn printMenu(){
    println!("PLease choose an encryption algorithm:");
    for i in 0..options.len(){
        println!("{}", options[i]);
    }
}

pub fn Menu(PATH: &mut String){
    const PREFIX: &str = "symmetric_encryption/";
    PATH.push_str(PREFIX);
    loop {
        printMenu();
        let mut r = super::getInput(PATH.clone(), 1, options.len());
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        r = match r {
            1 => super::aes::menu::Menu(PATH),
            2 => super::des::menu::Menu(PATH),
            3 => super::rc4::menu::Menu(PATH),
            _ => return
        };

        if r == RETURN_STATUS { break; }
    }

    PATH.drain(PATH.len() - PREFIX.len()..);
    return;
}