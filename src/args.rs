use std::error::Error;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(version, long_about = None)]
pub struct Args {
    #[arg(help = "The shellcode to encrypt and obfuscate")]
    pub shellcode: std::path::PathBuf,

    #[arg(
        long,
        value_enum,
        help = "Encryption method [aes, rc6, xor]",
        hide_possible_values = true
    )]
    pub encryption: Option<Encryption>,

    #[arg(
        long,
        value_enum,
        help = "Obfuscation method [ipv4, ipv6, uuid, mac_addr]",
        hide_possible_values = true
    )]
    pub obfuscation: Option<Obfuscation>,

    #[arg(help = "The key to encrypt the shellcode (path or 32 hexa char)")]
    pub key: Option<String>,

    #[arg(long, short, help = "The output file", default_value = "output.rs")]
    pub output: std::path::PathBuf,
}

impl Args {
    pub fn validate(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.shellcode.exists() {
            return Err("The shellcode file does not exist".into());
        }

        if self.encryption.is_some() && self.obfuscation.is_some() {
            return Err("Please select either an encryption or obfuscation method".into());
        }

        let res = self.validate_key();
        if res.is_err() {
            return res;
        }

        Ok(())
    }

    fn validate_key(&mut self) -> Result<(), Box<dyn Error>> {
        let key = match &self.key {
            Some(key) => key,
            None => return Ok(()),
        };

        let key_path = std::path::Path::new(key);
        let raw_key = if key_path.exists() {
            match Self::read_key(key_path) {
                Ok(key) => key,
                Err(e) => return Err(e.into()),
            }
        } else {
            key.clone()
        };

        if raw_key.is_empty() {
            return Err("The key is empty".into());
        }
        if raw_key.len() != 32 {
            return Err("The key must be 32 bytes long".into());
        }

        self.key = Some(raw_key);

        Ok(())
    }

    fn read_key(path: &std::path::Path) -> Result<String, Box<dyn Error>> {
        let key = std::fs::read_to_string(path)?;
        Ok(key)
    }
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum Encryption {
    Aes,
    Rc6,
    Xor,
}

impl Encryption {
    pub fn to_string(&self) -> String {
        match self {
            Encryption::Aes => "AES".to_string(),
            Encryption::Rc6 => "RC6".to_string(),
            Encryption::Xor => "XOR".to_string(),
        }
    }
}

#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum Obfuscation {
    Ipv4,
    Ipv6,
    Uuid,
    MacAddr,
}

impl Obfuscation {
    pub fn to_string(&self) -> String {
        match self {
            Obfuscation::Ipv4 => "IPv4".to_string(),
            Obfuscation::Ipv6 => "IPv6".to_string(),
            Obfuscation::Uuid => "UUID".to_string(),
            Obfuscation::MacAddr => "MAC Address".to_string(),
        }
    }
}
