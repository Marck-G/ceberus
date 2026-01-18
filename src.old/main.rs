mod cli;
mod compression;
mod crypto;

use clap::Parser;
use cli::Cli;

use crate::{cli::{generate_keys, generate_symmetric_key, Commands}, crypto::{load_public_key, verify_signature}};

// fn main() {
//     let cli = Cli::parse();

//     match &cli.command {
//         Commands::GenerateKeys { output, key_size } => {
//             if let Err(e) = generate_keys(&output, *key_size) {
//                 eprintln!("Error generando claves: {}", e);
//             }
//         }
//         Commands::GenerateSymmetricKey { public_key, output } => {
//             if let Err(e) = generate_symmetric_key(public_key.as_str(), output.as_str()) {
//                 eprintln!("Error generando clave simétrica: {}", e);
//             }
//         }
//     }
// }

pub fn main() {
    let pub_path = "/home/mguzman/Projects/katalyst/agrocs-java/cerberus/certs/public.pem";
    let token = "KLUv_QBY8QQAR25zRmtGNzk1b0gtSTZ2QS0yYW9GM3Bmc1JIYUF0QmNiRnZKLTk1Z2FGeDF2aXlkWDFPMm5URmpYakJJRkUyX1dGMkZERWpkQjdwMWxqanFHVnh1MXZSWlpaeG8yZHN0THBLRF9OMFpiaURORklNLjZsWU9femVTWE80QUVyVFBNcUtROUY3V0IxbG1YaTdLUE84Nkdaeml2YlNwMHc.AeCY6WXS1wQccn-QDjo0aR92Dnk4mXQU3NPr3wPn2kC8xfIBJE3QbjCYS0wk2eH-wTEi-kJAgqUGGBud1Ih7HhGdN1xJuqg_Tjvqac8mnmjL-LXFMvNOESNvcJ5hLzDtKthK0-QfRb5jxkkApxVp4rtXuQU_JRYwho0Ty9blbNk5iXdIunc725LvPsYzYWc6yVtTwH1qUe0Dp1tXaemA6cdII6lQUb1rt6KLpeufDnD99BSoHQe04tkFQicmn38MY6Yxq1Jg9LXqW01swBlbMr03GCQJbZhbdPK-QKGH-AfrcsD7XCQwb5rCYoBU7nWZEtfIUxQj2F5hZ6Umt68jLA";
    
    let public_key_pem = match std::fs::read(&pub_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprint!("File not found! {}", e);
            vec![0]
        }
    };

    let public_key = match load_public_key(&public_key_pem) {
        Ok(pk) => pk,
        Err(e) => {
            eprint!("Error loading file: {}", e);
            return;
        }
    };
    // Aquí debes parsear el token en "compressed_base64.signature_base64"
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        eprint!("Token mal formado, debe tener formato 'zip.sign'");
    }
    let compressed_base64 = parts[0];
    let signature_base64 = parts[1];
    let verf_result =
        match verify_signature(&public_key, compressed_base64.as_bytes(), signature_base64) {
            Ok(valid) => valid,
            Err(e) => {
                eprint!("Verification error: {}", e);
                false
            }
        };
    print!("Result: {}", verf_result);
}