![Deceiver Logo](banner.webp)

## Description

> [!note]
> This project is inspired by [NUL0x4C's HellShell](https://github.com/NUL0x4C/HellShell)

The goal of the project is to encrypt or obfuscate a payload, then generate a `.rs` file that contains the required functions to decrypt or deobfuscate the payload.

Deceiver takes padding into account, using [pkcs#7](https://en.wikipedia.org/wiki/PKCS_7) padding to adapt to every length of payload.

Deceiver will output the generated `.rs` file to a default `output.rs`.

## Installation

First, you need to have git and rust installed.

Then simply clone the project and run it with cargo.

```shell
git clone https://github.com/Code-Barru/deceiver.git
cd deceiver
cargo run --release -- <options>
```

By using cargo the first run will compile the project and therefore take some time. Subsequent uses will be instant.

## Usage

```shell
Usage: deceiver [OPTIONS] <SHELLCODE> [KEY]

Arguments:
  <SHELLCODE>  The shellcode to encrypt and obfuscate
  [KEY]        The key to encrypt the shellcode (path or 32 hexa char)

Options:
      --encryption <ENCRYPTION>    Encryption method [aes, rc6, xor]
      --obfuscation <OBFUSCATION>  Obfuscation method [ipv4, ipv6, uuid, mac_addr]
  -o, --output <OUTPUT>            The output file [default: output.rs]
  -h, --help                       Print help
  -V, --version                    Print version
```
