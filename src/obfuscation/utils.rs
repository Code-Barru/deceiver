use super::{ipv4, ipv6, mac_addr, uuid};
use crate::args::{Args, Obfuscation};

pub fn handler(args: &Args, shellcode: &Vec<u8>) -> Result<String, String> {
    let obfuscation = match args.obfuscation.as_ref() {
        Some(obfuscation) => obfuscation,
        None => return Err("No obfuscation method selected".to_string()),
    };

    match obfuscation {
        Obfuscation::Ipv4 => {
            let obfuscated = ipv4::obfuscate(shellcode);
            Ok(ipv4::format(obfuscated))
        }
        Obfuscation::Ipv6 => {
            let obfuscated = ipv6::obfuscate(shellcode);
            Ok(ipv6::format(obfuscated))
        }
        Obfuscation::MacAddr => {
            let obfuscated = mac_addr::obfuscate(shellcode);
            Ok(mac_addr::format(obfuscated))
        }
        Obfuscation::Uuid => {
            let obfuscated = uuid::obfuscate(shellcode);
            Ok(uuid::format(obfuscated))
        }
    }
}

pub fn format_strings(strings: Vec<String>, strings_per_line: usize) -> String {
    let mut formatted = String::from("[\n\t");
    for (i, string) in strings.iter().enumerate() {
        if i > 0 && i % strings_per_line == 0 {
            formatted.push_str("\n\t");
        }
        formatted.push_str(&format!("{:?}, ", string));
    }
    formatted.push_str("\n]");
    formatted
}
