use clap::{Parser, Subcommand};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::encrypt::Encrypter;
use openssl::rsa::Padding;
use rand::Rng;
use std::fs;

/// CLI para gestión de claves
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Genera claves RSA pública y privada
    GenerateKeys {
        #[arg(short, long)]
        output: String,
        #[arg(short = 's', long, default_value_t = 2048)]
        key_size: u32,
    },
    /// Genera y cifra una clave simétrica
    GenerateSymmetricKey {
        #[arg(short, long)]
        public_key: String,
        #[arg(short, long)]
        output: String,
    },
}



/// Genera claves pública y privada RSA
pub fn generate_keys(output: &str, key_size: u32) -> Result<(), String> {
    let rsa = Rsa::generate(key_size)
        .map_err(|e| format!("Error generando claves RSA: {}", e))?;

    let private_key_pem = rsa.private_key_to_pem()
        .map_err(|e| format!("Error serializando clave privada: {}", e))?;

    let public_key_pem = rsa.public_key_to_pem()
        .map_err(|e| format!("Error serializando clave pública: {}", e))?;

    fs::create_dir_all(output)
        .map_err(|e| format!("Error creando directorio: {}", e))?;

    fs::write(format!("{}/private.pem", output), private_key_pem)
        .map_err(|e| format!("Error escribiendo clave privada: {}", e))?;

    fs::write(format!("{}/public.pem", output), public_key_pem)
        .map_err(|e| format!("Error escribiendo clave pública: {}", e))?;

    println!("Claves generadas en '{}'", output);
    Ok(())
}

/// Genera una clave simétrica y la cifra con la clave pública
pub fn generate_symmetric_key(public_key_path: &str, output_path: &str) -> Result<(), String> {
    let public_key_pem = fs::read(public_key_path)
        .map_err(|e| format!("Error leyendo clave pública: {}", e))?;

    let public_key = PKey::public_key_from_pem(&public_key_pem)
        .map_err(|e| format!("Error parseando clave pública: {}", e))?;

    // Generar clave simétrica aleatoria de 32 bytes
    let symmetric_key: [u8; 32] = rand::thread_rng().gen();

    let rsa = public_key.rsa()
        .map_err(|e| format!("Error obteniendo RSA de la clave pública: {}", e))?;

    let mut encrypted = vec![0; rsa.size() as usize];

    let encrypted_len = rsa
        .public_encrypt(&symmetric_key, &mut encrypted, Padding::PKCS1_OAEP)
        .map_err(|e| format!("Error cifrando clave simétrica: {}", e))?;

    encrypted.truncate(encrypted_len);

    fs::write(output_path, encrypted)
        .map_err(|e| format!("Error escribiendo clave cifrada: {}", e))?;

    println!("Clave simétrica cifrada guardada en '{}'", output_path);
    Ok(())
}
