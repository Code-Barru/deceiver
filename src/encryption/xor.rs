use super::format_byte_arrays;

static DECRYPT_FUNCTION: &str = r#"
pub fn pkcs7_unpad(decrypted: &[u8]) -> Vec<u8> {
    if let Some(&last_byte) = decrypted.last() {
        let pad_len = last_byte as usize;
        if pad_len > 0 && pad_len <= decrypted.len()
            && decrypted[decrypted.len() - pad_len..].iter().all(|&b| b == last_byte) {
            return decrypted[..decrypted.len() - pad_len].to_vec();
        }
    }
    decrypted.to_vec()
}

pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    pkcs7_unpad(
        &ciphertext
            .iter()
            .zip(key.iter().cycle())
            .map(|(&x, &y)| x ^ y)
            .collect::<Vec<u8>>(),
    )
}
"#;
static MAIN_FUNCTION: &str = r#"
fn main() {
    let decrypted = decrypt(&KEY, &CIPHERTEXT);
    println!("{:?}", &decrypted);
}
"#;

pub fn pkcs7_pad(text: &Vec<u8>, block_size: usize) -> Vec<u8> {
    let mut padded = text.clone();
    let pad_len = block_size - (padded.len() % block_size);
    padded.extend(vec![pad_len as u8; pad_len]);
    padded
}

pub fn encrypt(key: &[u8], text: &Vec<u8>) -> Vec<u8> {
    let padded_text = pkcs7_pad(text, key.len());

    padded_text
        .iter()
        .zip(key.iter().cycle())
        .map(|(&x, &y)| x ^ y)
        .collect()
}

pub fn format(ciphertext: &[u8], key: &[u8]) -> String {
    format!(
        "static CIPHERTEXT: [u8; {}] = {};\n\nstatic KEY: [u8; {}] = {};{}{}",
        ciphertext.len(),
        format_byte_arrays(ciphertext),
        key.len(),
        format_byte_arrays(key),
        DECRYPT_FUNCTION,
        MAIN_FUNCTION
    )
}
