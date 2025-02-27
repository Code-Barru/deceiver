use std::path::PathBuf;

use crate::args::{Args, Obfuscation};

use colored::Colorize;

pub fn print_banner() {
    use colored::*;

    let colors = [
        Color::Blue,
        Color::Green,
        Color::Green,
        Color::Green,
        Color::Green,
        Color::Cyan,
    ];

    let banner =
        String::from("\n████████╗██████╗ ██╗ ██████╗██╗  ██╗███████╗████████╗███████╗██████╗\n")
            + "╚══██╔══╝██╔══██╗██║██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n"
            + "   ██║   ██████╔╝██║██║     █████╔╝ ███████╗   ██║   █████╗  ██████╔╝\n"
            + "   ██║   ██╔══██╗██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══╝  ██╔══██╗\n"
            + "   ██║   ██║  ██║██║╚██████╗██║  ██╗███████║   ██║   ███████╗██║  ██║\n"
            + "   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
            + "\n";

    for (i, line) in banner.lines().enumerate() {
        let color = colors[i % colors.len()];
        println!("{}", line.color(color));
    }
}

pub fn print_error(message: &str) {
    eprintln!("{}", message.red().bold());
}

pub fn print_args(args: &Args) {
    println!(
        "{} {}",
        "File:".cyan().bold(),
        args.shellcode.display().to_string().green().bold()
    );

    match &args.obfuscation {
        Some(obfuscation) => println!(
            "{} {}",
            "Obfuscation:".cyan().bold(),
            obfuscation.to_string().green().bold()
        ),
        None => println!("{} {}", "Obfuscation:".cyan().bold(), "None".red().bold()),
    }

    match &args.encryption {
        Some(encryption) => println!(
            "{} {}",
            "Encryption:".cyan().bold(),
            encryption.to_string().green().bold()
        ),
        None => println!("{} {}", "Encryption:".cyan().bold(), "None".red().bold()),
    }
}

pub fn print_success(file: PathBuf, args: &Args) {
    let method = if args.obfuscation.is_some() {
        "obfuscated"
    } else {
        "encrypted"
    };

    let sub_method = match &args.obfuscation {
        Some(obfuscation) => obfuscation.to_string(),
        None => args.encryption.as_ref().unwrap().to_string(),
    };

    print!(
        "\n{} {} {} {} {} {}\n",
        "Payload".cyan().bold(),
        method.green().bold(),
        "using".cyan().bold(),
        sub_method.green().bold(),
        "and saved to".cyan().bold(),
        file.display().to_string().green().bold()
    );
}

pub fn print_packages(args: &Args) {
    if args.obfuscation.is_some() {
        let obfs = args.obfuscation.as_ref().unwrap();
        if *obfs == Obfuscation::MacAddr {
            println!(
                "\n{}",
                "Note: The MacAddr obfuscation method requires the 'mac_address' package to be installed"
                    .yellow().bold()
            );
        } else if *obfs == Obfuscation::Uuid {
            println!(
                "\n{}",
                "Note: The Uuid obfuscation method requires the 'uuid' package to be installed"
                    .yellow()
                    .bold()
            );
        }
    }

    if args.encryption.is_some() {
        let enc = args.encryption.as_ref().unwrap();
        if *enc == crate::args::Encryption::Aes {
            println!(
                "\n{}",
                "Note: The AES encryption method requires the 'aes-gcm' package to be installed"
                    .yellow()
                    .bold()
            );
        }
    }
}
