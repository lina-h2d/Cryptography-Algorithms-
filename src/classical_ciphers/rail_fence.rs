use std::io;
use std::io::Write;

// Not used but can be useful later
fn print_matrix(matrix: Vec<Vec<char>>){
    for i in 0..matrix.len() {
        for j in 0..matrix[i].len() {
            print!("{}\t", matrix[i][j]);
        }
        println!()
    }
}

fn generate_matrix(text:  &str, rails: u8) -> Vec<Vec<char>>{
    let text = text.chars().filter(|c| c.is_ascii_alphabetic()).collect::<String>();
    let rails = rails as usize;
    let mut matrix: Vec<Vec<char>> = vec![vec!['.'; text.len()]; rails as usize];

    // First line
    for i in (0..text.len()).step_by(2 * (rails - 1)) {
        matrix[0][i] = text.chars().nth(i).unwrap();
    }

    for row in 1..rails - 1 {
        let mut i1;
        for i0 in (row..text.len()).step_by(2 * (rails - 1)) {
            matrix[row][i0] = text.chars().nth(i0).unwrap();      // Starting Rail

            i1 = i0 + 2 * (rails - 1) - 2 * row;
            if i1 >= text.len() { break; }
            matrix[row][i1] = text.chars().nth(i1).unwrap();    // Finishing Rail
        }
    }

    // Last line
    for i in (rails - 1..text.len()).step_by(2 * (rails - 1)) {
        matrix[rails - 1][i] = text.chars().nth(i).unwrap();
    }

    matrix
}

fn generate_matrix_decrypt(text: &str, rails: u8) -> Vec<Vec<char>>{
    let text = text.chars().filter(|c| c.is_ascii_alphabetic()).collect::<String>();
    let rails = rails as usize;
    let mut matrix: Vec<Vec<char>> = vec![vec!['.'; text.len()]; rails];

    let mut i = 0;

    // First Line
    for j in (0..text.len()).step_by(2 * (rails - 1)) {
        matrix[0][j] = text.chars().nth(i).unwrap();
        i += 1;
    }

    // Second to before last line
    for row in 1..rails - 1 {
        for j0 in (row..text.len()).step_by(2 * (rails - 1)) {
            matrix[row][j0] = text.chars().nth(i).unwrap();
            i += 1;

            let j1 = j0 + 2 * (rails - 1) - 2 * row;
            if j1 >= text.len() { break; }
            matrix[row][j1] = text.chars().nth(i).unwrap();
            i += 1;
        }
    }

    // Last Line
    for j in (rails - 1..text.len()).step_by(2 * (rails - 1)) {
        matrix[rails - 1][j] = text.chars().nth(i).unwrap();
        i += 1;
    }

    matrix
}

pub fn encrypt(text: &str, rails: u8) -> String {
    let mut result = String::new();
    let matrix = generate_matrix(text, rails);

    for row in 0..matrix.len() {
        result.push_str(matrix[row].iter().filter(|c| **c != '.').collect::<String>().as_str());
    }

    result
}

pub fn decrypt(text: &str, rails: u8) -> String {
    let mut result = String::new();
    let matrix = generate_matrix_decrypt(text, rails);
    let mut i: usize = 0;

    while i < matrix[0].len() {
        for row in 0..matrix.len() {
            result.push(matrix[row][i]);
            i += 1;
            if i >= matrix[0].len() { break; }
        }
        for row in 1..matrix.len() - 1 {
            result.push(matrix[matrix.len() - 1 - row][i]);
            i += 1;
            if i >= matrix[0].len() { break; }
        }
    }

    result
}

pub fn Menu(PATH: &mut String) -> usize {
    let mut buf = String::new();
    let mut rails = String::new();
    let r;
    const PREFIX: &str = "rail_fence/";

    PATH.push_str(PREFIX);
    r = super::getGenericOption(PATH.clone());
    if r == 3 {
        PATH.drain(PATH.len() - PREFIX.len()..);
        return 1;
    }

    print!("Enter text: ");               io::stdout().flush().unwrap();
    io::stdin().read_line(&mut buf).expect("Failed to read plaintext.");

    print!("Enter number of rails: ");      io::stdout().flush().unwrap();
    io::stdin().read_line(&mut rails).expect("Failed to read number of rails.");
    let rails = rails.trim().parse::<u8>().expect("Invalid rails number.");

    match r {
        1 => buf = encrypt(buf.as_str(), rails),
        2 => buf = decrypt(buf.as_str(), rails),
        _ => {}
    }

    println!("\nResult: {buf}");
    PATH.drain(PATH.len() - PREFIX.len()..);
    0
}