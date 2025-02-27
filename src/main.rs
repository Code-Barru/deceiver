use clap::Parser;

mod args;
mod encryption;
mod obfuscation;
mod ui;

use args::Args;

fn main() {
    let mut args = Args::parse();
    match args.validate() {
        Ok(_) => (),
        Err(e) => {
            ui::print_error(e.to_string().as_str());
            std::process::exit(1);
        }
    }

    if args.obfuscation.is_none() && args.encryption.is_none() {
        ui::print_error("Please select an obfuscation or encryption method");
        std::process::exit(1);
    }

    let file = args.shellcode.clone();
    let shellcode = match std::fs::read(&file) {
        Ok(shellcode) => shellcode,
        Err(e) => {
            ui::print_error(e.to_string().as_str());
            std::process::exit(1);
        }
    };

    ui::print_banner();
    ui::print_args(&args);

    let handler = if args.obfuscation.is_some() {
        obfuscation::handler
    } else if args.encryption.is_some() {
        encryption::handler
    } else {
        panic!("No handler found");
    };

    let file_str = match handler(&args, &shellcode) {
        Ok(file_str) => file_str,
        Err(e) => {
            ui::print_error(e.as_str());
            std::process::exit(1);
        }
    };

    let file = args.output.clone();
    if file.exists() {
        match std::fs::remove_file(&file) {
            Ok(_) => (),
            Err(e) => {
                ui::print_error(e.to_string().as_str());
                std::process::exit(1);
            }
        }
    }

    match std::fs::write(file, file_str) {
        Ok(_) => (),
        Err(e) => {
            ui::print_error(e.to_string().as_str());
            std::process::exit(1);
        }
    };

    ui::print_success(args.output.clone(), &args);
    ui::print_packages(&args);
}
