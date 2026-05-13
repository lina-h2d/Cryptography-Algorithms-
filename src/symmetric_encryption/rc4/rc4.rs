pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    //initialize the state array S
    let mut s = Vec::with_capacity(256);
    for i in 0..256 {
        s.push(i as u8);
    }

    //Key Scheduling Algorithm (KSA)
    let mut j = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    let mut i = 0;
    j = 0;
    let mut result = Vec::new();

    for byte in data.iter() {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;

        s.swap(i, j);

        let t = (s[i] as usize + s[j] as usize) % 256;
        let k = s[t];

        result.push(byte ^ k);
    }

    result
}

pub fn to_hex(data: &[u8]) -> String {
    let mut hex_string = String::new();

    for byte in data {
        hex_string.push_str(&format!("{:02X} ", byte));
    }

    hex_string.trim_end().to_string()
}

