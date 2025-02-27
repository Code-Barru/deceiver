use super::format_strings;
use std::net::Ipv4Addr;

static IMPORTS: &str = "use std::net::Ipv4Addr;";
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

    for ip_str in obfuscated.iter() {
        let ip: Ipv4Addr = ip_str.parse().expect("Invalid IP address format");
        shellcode.extend_from_slice(&ip.octets());
    }

    pkcs7_unpad(&shellcode)
}"#;
static MAIN_FUNCTION: &str = r#"
fn main() {
    let obfuscated_vec: Vec<String> = OBFUSCATED.iter().map(|&s| s.to_string()).collect();
    let shellcode = deobfuscate(&obfuscated_vec);
    println!("{:?}", &shellcode);
}
"#;

pub fn obfuscate(shellcode: &Vec<u8>) -> Vec<String> {
    let ipv4_vec = transform(shellcode);

    let mut obfuscated_shellcode = Vec::new();

    for ipv4 in ipv4_vec.iter() {
        obfuscated_shellcode.push(ipv4.to_string());
    }

    obfuscated_shellcode
}

pub fn transform(shellcode: &Vec<u8>) -> Vec<Ipv4Addr> {
    let mut padded_shellcode = shellcode.clone();
    let padding_len = 4 - (shellcode.len() % 4);
    padded_shellcode.extend(vec![padding_len as u8; padding_len]);

    let mut obfuscated_shellcode = Vec::new();

    for chunk in padded_shellcode.chunks(4) {
        let chunk: [u8; 4] = chunk.try_into().expect("Chunking failed");
        let ip = Ipv4Addr::from(chunk);
        obfuscated_shellcode.push(ip);
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
