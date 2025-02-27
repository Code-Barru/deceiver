use rand::random;

use crate::args::{Args, Encryption};

use super::{aes, rc6, xor};

pub fn handler(args: &Args, shellcode: &Vec<u8>) -> Result<String, String> {
    let encryption = match args.encryption.as_ref() {
        Some(encryption) => encryption,
        None => return Err("No encryption method selected".to_string()),
    };

    let key = if args.key.is_some() {
        args.key.as_ref().unwrap().as_bytes()
    } else {
        &random::<[u8; 32]>()
    };

    match encryption {
        Encryption::Aes => {
            let (ciphered, nonce) = aes::encrypt(key, &shellcode);
            Ok(aes::format(&ciphered, &nonce, key))
        }
        Encryption::Xor => {
            let ciphered = xor::encrypt(key, &shellcode);
            Ok(xor::format(&ciphered, key))
        }
        Encryption::Rc6 => {
            let ciphered = rc6::encrypt(key, &shellcode);
            Ok(rc6::format(&ciphered, key))
        }
    }
}

pub fn format_byte_arrays(bytes: &[u8]) -> String {
    let bytes_per_line = 10;
    let mut formatted = String::from("[\n\t");

    for (i, byte) in bytes.iter().enumerate() {
        formatted.push_str(&format!("0x{:02X}, ", byte));

        if (i + 1) % bytes_per_line == 0 {
            formatted.push_str("\n\t");
        }
    }

    formatted.push_str("\n]");
    formatted
}
