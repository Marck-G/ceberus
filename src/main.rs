mod cli;

use clap::Parser;
use cli::Cli;

use crate::cli::{generate_keys, generate_symmetric_key, Commands};

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateKeys { output, key_size } => {
            if let Err(e) = generate_keys(&output, *key_size) {
                eprintln!("Error generando claves: {}", e);
            }
        }
        Commands::GenerateSymmetricKey { public_key, output } => {
            if let Err(e) = generate_symmetric_key(public_key.as_str(), output.as_str()) {
                eprintln!("Error generando clave simétrica: {}", e);
            }
        }
    }
}