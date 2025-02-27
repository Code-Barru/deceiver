use mac_address::MacAddress;

use crate::obfuscation::format_strings;

static IMPORTS: &str = "use mac_address::MacAddress;";
static DEOBFUSCATE_FUNCTION: &str = r#"
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
pub fn deobfuscate(obfuscated: &Vec<String>) -> Vec<u8> {
    let mut shellcode = Vec::new();

    for mac_str in obfuscated.iter() {
        let mac: MacAddress = mac_str.parse().expect("Invalid MAC address format");
        shellcode.extend_from_slice(&mac.bytes());
    }

    pkcs7_unpad(&shellcode)
}"#;
static MAIN_FUNCTION: &str = r#"
fn main() {
    let obfuscated_vec: Vec<String> = OBFUSCATED.iter().map(|&s| s.to_string()).collect();
    let shellcode = deobfuscate(&obfuscated_vec);
    println!("{:?}", &shellcode);
}"#;

pub fn obfuscate(shellcode: &Vec<u8>) -> Vec<String> {
    let mac_vec = transform(shellcode);

    let mut obfuscated_shellcode = Vec::new();

    for mac in mac_vec.iter() {
        obfuscated_shellcode.push(mac.to_string());
    }

    obfuscated_shellcode
}

pub fn transform(shellcode: &Vec<u8>) -> Vec<MacAddress> {
    let mut padded_shellcode = shellcode.clone();
    let padding_length = 6 - (shellcode.len() % 6);
    padded_shellcode.extend(vec![padding_length as u8; padding_length]);

    let mut obfuscated_shellcode = Vec::new();

    for chunk in padded_shellcode.chunks(6) {
        let chunk: [u8; 6] = chunk.try_into().expect("Chunking failed");
        let mac = MacAddress::new(chunk);
        obfuscated_shellcode.push(mac);
    }

    obfuscated_shellcode
}

pub fn format(obfuscated: Vec<String>) -> String {
    format!(
        "{}\n\nstatic OBFUSCATED: [&str; {}] = {};\n{}\n{}",
        IMPORTS,
        obfuscated.len(),
        format_strings(obfuscated, 4),
        DEOBFUSCATE_FUNCTION,
        MAIN_FUNCTION
    )
}
