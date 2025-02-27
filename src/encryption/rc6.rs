use crate::encryption::format_byte_arrays;

const R: usize = 20;
const P: u32 = 0xB7E15163;
const Q: u32 = 0x9E3779B9;

static CONSTS: &str = r#"const R: usize = 20;
const P: u32 = 0xB7E15163;
const Q: u32 = 0x9E3779B9;
"#;
static DECRYPT_FUNCTION: &str = r#"
fn key_schedule(key: &[u8]) -> Vec<u32> {
    let mut key_u32 = vec![0u32; (key.len() + 3) / 4];
    for (i, chunk) in key.chunks(4).enumerate() {
        key_u32[i] = chunk.iter().rev().fold(0, |acc, &b| (acc << 8) | b as u32);
    }

    let mut s = vec![0u32; 2 * R + 4];
    s[0] = P;
    for i in 1..s.len() {
        s[i] = s[i - 1].wrapping_add(Q);
    }

    let mut a = 0u32;
    let mut b = 0u32;
    let mut i = 0;
    let mut j = 0;
    let cycles = 3 * s.len().max(key_u32.len());

    for _ in 0..cycles {
        s[i] = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        a = s[i];
        key_u32[j] = key_u32[j]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left((a.wrapping_add(b)) as u32);
        b = key_u32[j];
        i = (i + 1) % s.len();
        j = (j + 1) % key_u32.len();
    }

    s
}

fn decrypt_block(s: &[u32], ct: [u32; 4]) -> [u32; 4] {
    let (mut a, mut b, mut c, mut d) = (ct[0], ct[1], ct[2], ct[3]);
    c = c.wrapping_sub(s[2 * R + 3]);
    a = a.wrapping_sub(s[2 * R + 2]);
    for i in (1..=R).rev() {
        (a, b, c, d) = (d, a, b, c);

        let u = (d.wrapping_mul(2).wrapping_add(1)).rotate_left(5);
        let t = (b.wrapping_mul(2).wrapping_add(1)).rotate_left(5);
        c = c ^ s[2 * i + 1];
        c = c.rotate_right(t as u32).wrapping_sub(u);
        a = a ^ s[2 * i];
        a = a.rotate_right(u as u32).wrapping_sub(t);
    }
    d = d.wrapping_sub(s[1]);
    b = b.wrapping_sub(s[0]);

    [a, b, c, d]
}

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

pub fn decrypt(key: &[u8], encrypted_shellcode: &[u8]) -> Vec<u8> {
    let s = key_schedule(&key);
    let mut decrypted = Vec::new();

    for chunk in encrypted_shellcode.chunks(16) {
        let mut ct = [0u32; 4];
        for (i, byte) in chunk.iter().enumerate() {
            ct[i / 4] |= (*byte as u32) << (8 * (i % 4));
        }

        let pt = decrypt_block(&s, ct);
        for &word in &pt {
            for i in 0..4 {
                decrypted.push((word >> (8 * i)) as u8);
            }
        }
    }

    pkcs7_unpad(&decrypted)
}
"#;
static MAIN_FUNCTION: &str = r#"
fn main() {
    let decrypted = decrypt(&KEY, &CIPHERTEXT);
    println!("{:?}", &decrypted);
}
"#;

fn key_schedule(key: &[u8]) -> Vec<u32> {
    let mut key_u32 = vec![0u32; (key.len() + 3) / 4];
    for (i, chunk) in key.chunks(4).enumerate() {
        key_u32[i] = chunk.iter().rev().fold(0, |acc, &b| (acc << 8) | b as u32);
    }

    let mut s = vec![0u32; 2 * R + 4];
    s[0] = P;
    for i in 1..s.len() {
        s[i] = s[i - 1].wrapping_add(Q);
    }

    let mut a = 0u32;
    let mut b = 0u32;
    let mut i = 0;
    let mut j = 0;
    let cycles = 3 * s.len().max(key_u32.len());

    for _ in 0..cycles {
        s[i] = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        a = s[i];
        key_u32[j] = key_u32[j]
            .wrapping_add(a)
            .wrapping_add(b)
            .rotate_left((a.wrapping_add(b)) as u32);
        b = key_u32[j];
        i = (i + 1) % s.len();
        j = (j + 1) % key_u32.len();
    }

    s
}

fn encrypt_block(s: &[u32], pt: [u32; 4]) -> [u32; 4] {
    let (mut a, mut b, mut c, mut d) = (pt[0], pt[1], pt[2], pt[3]);
    b = b.wrapping_add(s[0]);
    d = d.wrapping_add(s[1]);
    for i in 1..=R {
        let t = (b.wrapping_mul(2).wrapping_add(1)).rotate_left(5);
        let u = (d.wrapping_mul(2).wrapping_add(1)).rotate_left(5);
        a = a.wrapping_add(t).rotate_left(u as u32) ^ s[2 * i];
        c = c.wrapping_add(u).rotate_left(t as u32) ^ s[2 * i + 1];

        (a, b, c, d) = (b, c, d, a);
    }

    a = a.wrapping_add(s[2 * R + 2]);
    c = c.wrapping_add(s[2 * R + 3]);

    [a, b, c, d]
}

pub fn encrypt(key: &[u8], shellcode: &Vec<u8>) -> Vec<u8> {
    let s = key_schedule(&key);
    let mut encrypted = Vec::new();
    let mut padded_shellcode = shellcode.clone();

    // PKCS#7 Padding
    let pad_len = 16 - (padded_shellcode.len() % 16);
    padded_shellcode.extend(vec![pad_len as u8; pad_len]);

    for chunk in padded_shellcode.chunks(16) {
        let mut pt = [0u32; 4];
        for (i, byte) in chunk.iter().enumerate() {
            pt[i / 4] |= (*byte as u32) << (8 * (i % 4));
        }

        let ct = encrypt_block(&s, pt);
        for &word in &ct {
            for i in 0..4 {
                encrypted.push((word >> (8 * i)) as u8);
            }
        }
    }

    encrypted
}

pub fn format(ciphered: &[u8], key: &[u8]) -> String {
    format!(
        "{}\nstatic CIPHERTEXT: [u8; {}] = {};\n\nstatic KEY: [u8; {}] = {};\n{}{}",
        CONSTS,
        ciphered.len(),
        format_byte_arrays(ciphered),
        key.len(),
        format_byte_arrays(key),
        DECRYPT_FUNCTION,
        MAIN_FUNCTION
    )
}
