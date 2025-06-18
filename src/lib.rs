use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jstring};
use jni::JNIEnv;

mod compression;
mod crypto;
mod utils;

use utils::create_token;

use crate::compression::decompress_from_base64;
use crate::crypto::{
    decrypt_from_base64, decrypt_symmetric_key, load_private_key, load_public_key, verify_signature,
};
use crate::utils::throw_java_exception;

#[no_mangle]
pub extern "system" fn Java_org_kcramsolutions_jcerberus_TokenLib_createToken(
    env: &mut JNIEnv,
    _class: JClass,
    header: JString,
    payload: JString,
    private_key_path: JString,
    encrypted_sym_key_path: JString,
) -> jstring {
    // Convertir JString a Rust String
    let header: String = env.get_string(&header).expect("Invalid header").into();
    let payload: String = env.get_string(&payload).expect("Invalid payload").into();
    let private_key_path: String = env
        .get_string(&private_key_path)
        .expect("Invalid key path")
        .into();
    let encrypted_sym_key_path: String = env
        .get_string(&encrypted_sym_key_path)
        .expect("Invalid sym key path")
        .into();

    // Llamar a la función Rust normal que devuelve Result<String, String>
    match create_token(
        &header,
        &payload,
        &private_key_path,
        &encrypted_sym_key_path,
    ) {
        Ok(token) => **env.new_string(token).expect("Couldn't create Java string!"),
        Err(err) => {
            throw_java_exception(env, &err);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_kcramsolutions_jcerberus_TokenLib_verify(
    env: &mut JNIEnv,
    _class: JClass,
    public_key_path: JString,
    token: JString,
) -> jboolean {
    // Convertir argumentos Java a Rust Strings
    let public_key_path: String = match env.get_string(&public_key_path) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_java_exception(env, &format!("Clave pública inválida: {:?}", e));
            return 0; // falso
        }
    };

    let token: String = match env.get_string(&token) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_java_exception(env, &format!("Token inválido: {:?}", e));
            return 0;
        }
    };
    // Cargar clave pública desde PEM
    let public_key_pem = match std::fs::read(&public_key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            throw_java_exception(env, &format!("Error leyendo clave pública: {}", e));
            return 0;
        }
    };

    let public_key = match load_public_key(&public_key_pem) {
        Ok(pk) => pk,
        Err(e) => {
            throw_java_exception(env, &format!("Error cargando clave pública: {}", e));
            return 0;
        }
    };
    // Aquí debes parsear el token en "compressed_base64.signature_base64"
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        throw_java_exception(env, "Token mal formado, debe tener formato 'zip.sign'");
        return 0;
    }
    let compressed_base64 = parts[0];
    let signature_base64 = parts[1];
    match verify_signature(&public_key, compressed_base64.as_bytes(), signature_base64) {
        Ok(valid) => {
            if valid {
                1
            } else {
                0
            }
        }
        Err(e) => {
            throw_java_exception(env, &format!("Error verificando firma: {}", e));
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_kcramsolutions_jcerberus_TokenLib_extractTokenData(
    env: &mut JNIEnv,
    _class: JClass,
    token: JString,
    private_key_path: JString,
    encrypted_sym_key_path: JString,
) -> jstring {
    // Convertir parámetros Java a String de Rust
    let token: String = match env.get_string(&token) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_java_exception(env, &format!("Token inválido: {:?}", e));
            return std::ptr::null_mut();
        }
    };

    let private_key_path: String = match env.get_string(&private_key_path) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_java_exception(env, &format!("Clave privada inválida: {:?}", e));
            return std::ptr::null_mut();
        }
    };

    let encrypted_sym_key_path: String = match env.get_string(&encrypted_sym_key_path) {
        Ok(s) => s.into(),
        Err(e) => {
            throw_java_exception(env, &format!("Clave simétrica inválida: {:?}", e));
            return std::ptr::null_mut();
        }
    };

    // Separar token: "compressed_base64.signature_base64"
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        throw_java_exception(env, "Token mal formado, debe tener formato 'zip.sign'");
        return std::ptr::null_mut();
    }
    let compressed_base64 = parts[0];

    // Descomprimir token
    let decompressed = match decompress_from_base64(compressed_base64) {
        Ok(data) => data,
        Err(e) => {
            throw_java_exception(env, &format!("Error descomprimiendo token: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Separar: "encrypted_header_base64.encrypted_payload_base64"
    let inner_parts: Vec<&str> = decompressed.split('.').collect();
    if inner_parts.len() != 2 {
        throw_java_exception(
            env,
            "Contenido mal formado, debe tener formato 'header.payload'",
        );
        return std::ptr::null_mut();
    }
    let encrypted_header = inner_parts[0];
    let encrypted_payload = inner_parts[1];

    // Cargar clave privada
    let private_key = match load_private_key(&private_key_path) {
        Ok(key) => key,
        Err(e) => {
            throw_java_exception(env, &format!("Error cargando clave privada: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Desencriptar clave simétrica
    let symmetric_key = match decrypt_symmetric_key(&encrypted_sym_key_path, &private_key) {
        Ok(key) => key,
        Err(e) => {
            throw_java_exception(env, &format!("Error descifrando clave simétrica: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Desencriptar header
    let header = match decrypt_from_base64(encrypted_header, &symmetric_key) {
        Ok(data) => data,
        Err(e) => {
            throw_java_exception(env, &format!("Error desencriptando header: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Desencriptar payload
    let payload = match decrypt_from_base64(encrypted_payload, &symmetric_key) {
        Ok(data) => data,
        Err(e) => {
            throw_java_exception(env, &format!("Error desencriptando payload: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Crear JSON de respuesta para simplificar entrega a Java
    let json_result = format!(r#"{{"header": {}, "payload": {}}}"#, header, payload);

    match env.new_string(json_result) {
        Ok(result) => **result,
        Err(e) => {
            throw_java_exception(env, &format!("Error devolviendo resultado: {:?}", e));
            std::ptr::null_mut()
        }
    }
}
