use std::fs;

use openssl::{pkey::{PKey, Private}, rsa::{Padding, Rsa}};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use base64::{engine::general_purpose, Engine as _};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use openssl::sign::Verifier;

pub fn load_private_key(key: &str) -> Result<PKey<Private>, String> {
    let key_data = fs::read(key)
        .map_err(|e| format!("Error leyendo la clave privada: {}", e))?;

    let rsa = Rsa::private_key_from_pem(&key_data)
        .map_err(|e| format!("Error parseando clave privada PEM: {}", e))?;

    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| format!("Error convirtiendo clave privada: {}", e))?;

    Ok(pkey)
}

/// Carga una clave pública directamente desde un PEM (sin certificado)
pub fn load_public_key(pem_bytes: &[u8]) -> Result<PKey<openssl::pkey::Public>, String> {
    let public_key = PKey::public_key_from_pem(pem_bytes)
        .map_err(|e| format!("Error leyendo clave pública desde PEM: {}", e))?;

    Ok(public_key)
}

pub fn decrypt_symmetric_key(
    encrypted_key_path: &str,
    private_key: &PKey<openssl::pkey::Private>
) -> Result<Vec<u8>, String> {
    let encrypted_key = fs::read(encrypted_key_path)
        .map_err(|e| format!("Error leyendo la clave simétrica cifrada: {}", e))?;

    let rsa = private_key.rsa()
        .map_err(|e| format!("Error obteniendo RSA de la clave privada: {}", e))?;

    let mut decrypted_key = vec![0; rsa.size() as usize];

    let decrypted_len = rsa
        .private_decrypt(&encrypted_key, &mut decrypted_key, Padding::PKCS1_OAEP)
        .map_err(|e| format!("Error descifrando la clave simétrica: {}", e))?;

    decrypted_key.truncate(decrypted_len);

    Ok(decrypted_key)
}

/// Cifra un texto plano con AES-GCM y lo devuelve en Base64URL
pub fn encrypt_to_base64(plaintext: &str, symmetric_key: &[u8]) -> Result<String, String> {
    if symmetric_key.len() != 32 {
        return Err("La clave simétrica debe tener 32 bytes (256 bits)".to_string());
    }

    let key = Key::<Aes256Gcm>::from_slice(symmetric_key);
    let cipher = Aes256Gcm::new(key);

    // Generar un nonce aleatorio (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Cifrar
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Error cifrando: {}", e))?;

    // Concatenar nonce + ciphertext para que el receptor pueda descifrar
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    // Codificar en Base64URL sin padding
    let base64 = general_purpose::URL_SAFE_NO_PAD.encode(combined);

    Ok(base64)
}

/// Desencripta una cadena base64url cifrada con AES-GCM y devuelve el String original
pub fn decrypt_from_base64(base64_data: &str, symmetric_key: &[u8]) -> Result<String, String> {
    if symmetric_key.len() != 32 {
        return Err("La clave simétrica debe tener 32 bytes (256 bits)".to_string());
    }

    // Decodificar desde Base64URL sin padding
    let encrypted_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(base64_data)
        .map_err(|e| format!("Error decodificando Base64: {}", e))?;

    if encrypted_bytes.len() < 12 {
        return Err("Datos cifrados inválidos: tamaño insuficiente para el nonce".to_string());
    }

    // Separar el nonce (primeros 12 bytes)
    let (nonce_bytes, ciphertext) = encrypted_bytes.split_at(12);

    let key = Key::<Aes256Gcm>::from_slice(symmetric_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Desencriptar
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Error desencriptando: {}", e))?;

    // Convertir a String
    let result = String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Error decodificando UTF-8: {}", e))?;

    Ok(result)
}

/// Firma un mensaje con clave privada RSA usando SHA256 y devuelve la firma en Base64URL
pub fn sign_message(private_key: &PKey<openssl::pkey::Private>, message: &[u8]) -> Result<String, String> {
    let mut signer = Signer::new(MessageDigest::sha256(), private_key)
        .map_err(|e| format!("Error creando signer: {}", e))?;

    signer.update(message)
        .map_err(|e| format!("Error actualizando signer: {}", e))?;

    let signature = signer.sign_to_vec()
        .map_err(|e| format!("Error generando firma: {}", e))?;

    let signature_base64 = general_purpose::URL_SAFE_NO_PAD.encode(signature);

    Ok(signature_base64)
}

/// Verifica una firma dada la clave pública, el mensaje original y la firma en base64url
pub fn verify_signature(
    public_key: &PKey<openssl::pkey::Public>,
    message: &[u8],
    signature_base64: &str
) -> Result<bool, String> {
    let signature = general_purpose::URL_SAFE_NO_PAD
        .decode(signature_base64)
        .map_err(|e| format!("Error decodificando firma Base64: {}", e))?;

    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key)
        .map_err(|e| format!("Error creando verifier: {}", e))?;

    verifier.update(message)
        .map_err(|e| format!("Error actualizando verifier: {}", e))?;

    let result = verifier.verify(&signature)
        .map_err(|e| format!("Error verificando firma: {}", e))?;

    Ok(result)
}