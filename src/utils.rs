use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
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

/// Helper to convert a C string (`*const c_char`) to an owned Rust `String`.
/// Returns `None` if the input pointer is null or the string is not valid UTF-8.
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer. The caller
/// must ensure that `c_str` is a valid, null-terminated C string pointer.
fn c_char_to_rust_string(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() {
        return None;
    }
    // SAFETY: We are trusting the caller to provide a valid, null-terminated C string.
    // If it's not, this could lead to undefined behavior.
    unsafe {
        CStr::from_ptr(c_str)
            .to_str() // Convert CStr to &str (can fail if not valid UTF-8)
            .map(|s| s.to_owned()) // Convert &str to owned String
            .ok() // Convert Result<String, _> to Option<String>
    }
}