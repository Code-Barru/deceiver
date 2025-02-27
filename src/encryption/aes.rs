use super::format_byte_arrays;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::Rng;

static IMPORTS: &str = "use aes_gcm::aead::Aead;\nuse aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};\n";
static DECRYPT_FUNCTION: &str = r#"
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<aes_gcm::aes::Aes256>::from_slice(key));
    match cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
        Ok(decrypted) => decrypted,
        Err(_) => panic!("Failed to decrypt"),
    }
}
"#;
static MAIN_FUNCTION: &str = r#"
fn main() {
    let decrypted = decrypt(&KEY, &NONCE, &CIPHERTEXT);
    println!("{:?}", &decrypted);
}
"#;

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new(Key::<aes_gcm::aes::Aes256>::from_slice(key));
    let nonce: [u8; 12] = rand::rng().random();
    let ciphertext = match cipher.encrypt(Nonce::from_slice(&nonce), plaintext) {
        Ok(ciphertext) => ciphertext,
        Err(_) => panic!("Failed to encrypt"),
    };
    (ciphertext, nonce.to_vec())
}

pub fn format(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> String {
    format!(
        "{}\nstatic CIPHERTEXT: [u8; {}] = {};\n\nstatic NONCE: [u8; {}] = {};\n\nstatic KEY: [u8; {}] = {};\n{}{}",
        IMPORTS,
        ciphertext.len(),
        format_byte_arrays(ciphertext),
        nonce.len(),
        format_byte_arrays(nonce),
        key.len(),
        format_byte_arrays(key),
        DECRYPT_FUNCTION,
        MAIN_FUNCTION
    )
}
