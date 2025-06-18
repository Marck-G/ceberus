use std::fs;
use openssl::pkey::PKey;

use crate::crypto::{decrypt_from_base64, decrypt_symmetric_key, load_private_key, encrypt_to_base64, sign_message};
use crate::compression::compress_to_base64;
use jni::JNIEnv;

pub fn throw_java_exception(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("org/kcramsolutions/jcerberus/TokenException", message);
    // El resultado se puede ignorar porque solo interesa lanzar la excepción
}

pub fn create_token(
    header_json: &str,
    payload_json: &str,
    private_key_path: &str,
    encrypted_symmetric_key_path: &str,
) -> Result<String, String> {
    // 1. Cargar clave privada
    let private_key = load_private_key(&private_key_path)?;

    // 2. Cargar clave simétrica cifrada y descifrarla con la clave privada
    let symmetric_key = decrypt_symmetric_key(&encrypted_symmetric_key_path, &private_key)?;

    // 3. Cifrar header y payload con AES-GCM + clave simétrica
    let encrypted_header = encrypt_to_base64(header_json, &symmetric_key)?;
    let encrypted_payload = encrypt_to_base64(payload_json, &symmetric_key)?;

    // 4. Concatenar con punto
    let combined = format!("{}.{}", encrypted_header, encrypted_payload);

    // 5. Comprimir y codificar
    let compressed = compress_to_base64(&combined)?;

    // 6. Firmar con clave privada (convertir compressed a bytes)
    let signature = sign_message(&private_key, compressed.as_bytes())?;

    // 7. Construir token final
    let token = format!("{}.{}", compressed, signature);

    Ok(token)
}