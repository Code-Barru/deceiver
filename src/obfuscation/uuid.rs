use uuid::Uuid;

use crate::obfuscation::format_strings;

static IMPORTS: &str = "use uuid::Uuid;";
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

    for uuid_str in obfuscated.iter() {
        let uuid: Uuid = uuid_str.parse().expect("Invalid UUID format");
        let bytes = uuid.as_bytes();

        // Reorder bytes according to UUID format
        shellcode.push(bytes[3]);
        shellcode.push(bytes[2]);
        shellcode.push(bytes[1]);
        shellcode.push(bytes[0]);
        shellcode.push(bytes[5]);
        shellcode.push(bytes[4]);
        shellcode.push(bytes[7]);
        shellcode.push(bytes[6]);
        shellcode.extend_from_slice(&bytes[8..16]);
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
    let uuid_vec = transform(shellcode);

    let mut obfuscated_shellcode = Vec::new();

    for uuid in uuid_vec.iter() {
        obfuscated_shellcode.push(uuid.to_string());
    }

    obfuscated_shellcode
}

pub fn transform(shellcode: &Vec<u8>) -> Vec<Uuid> {
    let mut padded_shellcode = shellcode.clone();
    let padding_len = 16 - (shellcode.len() % 16);
    padded_shellcode.extend(vec![padding_len as u8; padding_len]);

    let mut obfuscated_shellcode = Vec::new();

    for chunk in padded_shellcode.chunks(16) {
        let chunk: [u8; 16] = chunk.try_into().expect("Chunking failed");
        let uuid = Uuid::from_bytes_le(chunk);
        obfuscated_shellcode.push(uuid);
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
