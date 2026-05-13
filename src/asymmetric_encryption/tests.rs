
#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use num_bigint::{BigUint, RandBigInt};
    use rand::thread_rng;
    use crate::asymmetric_encryption::RSA::{decrypt, encrypt, rsa_generate_key_pair};
    use crate::asymmetric_encryption::DH_key_exchange::{DH_generate_key_pair,DH_shared_secret,MODP_2048};
    use crate::asymmetric_encryption::ElGamal::{ElGamal_generate_keys, ElGamal_decrypt, ElGamal_encrypt};

    #[test]
    fn generate_key_pair(){
        let (n,e,d) = rsa_generate_key_pair(512, 5);
        println!("n: 0x{:X}", n);
        println!("e: 0x{:X}", e);
        println!("d: 0x{:X}", d);
    }
    #[test]
    fn test_rsa_encrypt_decrypt() {
        // // Regenerated these 2, worked
        // let n_hex = "BEAB161A8B1B697ED1A0C7139E925B58FE9B76A5795CDD976A36E8500E3E7C029A628943EBD29D37D475D49C160D1D98101F252087CAA83B0AE2A94543931ECD";
        // let d_hex = "55266AD4A7D33225E4D07C979275A23DF856CD81D0D55C50C6AA86CD59CF25E9EE57D363CF9CAC3D5FA354E3424739572C555F3638CCE4909FD2416C4EEBBAB1";

        // // Regenerated these 3, worked
        // let n_hex = "6D4C1443175A3B78E69A46C742BA88C4F3F226642889C100BC21C961A986649E2D970DF232C6DB1DB8CB5D23B27A7D8104D15697E3313555627D7263CA17D96D";
        // let d_hex = "911AD04BC255295FF9C818EFB2C7B38CC7D254E5E46BFEB0DB14802808C9440A7E7B2BC8509495953F507E8C56A6EFFCB2FC14D4A788590F618806277A17349";

        // let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).unwrap();
        // let d = BigUint::parse_bytes(d_hex.as_bytes(), 16).unwrap();
        // let e = BigUint::from(0x10001u32);

        let (n,e,d) = rsa_generate_key_pair(512, 5);

        // let message = Vec::from([0x0C, 0x13]); // Worked with this
        let message = Vec::from("HELLO WORLD !"); // Worked with this
        println!("------------------------- Encryption -------------------------");
        let ciphertext = encrypt(&message, &e, &n);
        println!("ciphertext: {:?}", ciphertext);
        println!("------------------------- Decryption -------------------------");
        let decrypted = decrypt(&ciphertext, &d, &n);
        println!("decrypted: {:?}", decrypted);

        assert_eq!(message, decrypted.as_slice());
    }
    #[test]
    fn test_DH_key_exchange() {
        let g = BigUint::from(2u32);
        let (alice_private , alice_public)  = DH_generate_key_pair(&*MODP_2048, &g);
        let (bob_private , bob_public)  = DH_generate_key_pair(&*MODP_2048,&g);
        let alice_shared_secret = DH_shared_secret(&alice_private, &bob_public, &*MODP_2048);
        let bob_shared_secret = DH_shared_secret(&bob_private, &alice_public, &*MODP_2048);
        assert_eq!(alice_shared_secret, bob_shared_secret, "Shared secrets should be the same");
    }

lazy_static!{
    pub static ref SECURE_PRIME: BigUint = BigUint::parse_bytes(b"6942120798175882080594457812669318587080243130900436510867221614039874562649870591346956996743843800335323156501717076284789981677900515939965331468577627", 10).unwrap();
    pub static ref ANOTHER_SECURE_PRIME: BigUint  = BigUint::parse_bytes(b"13352635493652824167715215077523564732081557266175750779626347670024901835121453931635721885617436238301897405897613394213979133513060312480692170686761343",10).unwrap();
}

    #[test]
    fn test_elgamal_encryption_decryption() {
        use super::*;
        use num_bigint::{BigUint, RandBigInt};
        use rand::thread_rng;

        let p = SECURE_PRIME.clone();
        let g = BigUint::from(2u32);
        let mut rng = thread_rng();

        let private_key = rng.gen_biguint_range(&BigUint::from(2u32), &(p.clone() - BigUint::from(2u32) ));

        let public_key = g.modpow(&private_key, &p);

        let message = rng.gen_biguint_range(&BigUint::from(2u32), &(p.clone() - BigUint::from(2u32)));

        let (ciphertext, ephemeral_key) = ElGamal_encrypt(&message, &public_key, &p, &g);

        let decrypted_message = ElGamal_decrypt(&ciphertext, &ephemeral_key, &p, &private_key);

        assert_eq!(message, decrypted_message, "Decryption failed: Messages do not match!");
    }


}