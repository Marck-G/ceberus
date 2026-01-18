use j4rs::{errors::J4RsError, prelude::*, InvocationArg};
use j4rs_derive::call_from_java;

mod compression;
mod crypto;
mod utils;

use utils::create_token;

use crate::compression::decompress_from_base64;
use crate::crypto::{
    decrypt_from_base64, decrypt_symmetric_key, load_private_key, load_public_key, verify_signature,
};
use crate::utils::throw_java_exception;

#[call_from_java("org.kcramsolutions.jcerberus.TokenLib.nCreateToken")]
fn j_create_token(
    header_instance: Instance,
    body_instance: Instance,
    private_instance: Instance,
    encrypte_instance: Instance,
) -> Result<Instance, J4RsError> {
    let jvm = Jvm::attach_thread()?;
    let headers: Option<String> = jvm.to_rust(header_instance)?;
    let body: Option<String> = jvm.to_rust(body_instance)?;
    let priv_key_path: Option<String> = jvm.to_rust(private_instance)?;
    let key_path: Option<String> = jvm.to_rust(encrypte_instance)?;
    // checkin the data
    let he_json = headers.unwrap_or_else(|| {
        tracing::warn!("Cerberus: Empty headers");
        "".to_string()
    });
    let bd_json = body.unwrap_or_else(|| {
        tracing::warn!("Cerberus: Empty headers");
        "".to_string()
    });

    let ptv_path = priv_key_path.unwrap_or_else(|| {
        tracing::error!("Cerberus: null private key!");
        "null".to_string()
    });

    let rsa_path = key_path.unwrap_or_else(|| {
        tracing::error!("Cerberus: null symmetric key path!");
        "null".to_string()
    });

    if ptv_path.eq(&"null".to_string()) || rsa_path.eq(&"null".to_string()) {
        return Err(J4RsError::JavaError("Null private key path".to_string()));
    }

    let out: String = match create_token(&he_json, &bd_json, &ptv_path, &rsa_path) {
        Ok(token) => token,
        Err(error) => {
            tracing::error!("Cerberus: {}", error);
            "null".to_string()
        }
    };

    if out.eq(&"null".to_string()) {
        return Err(J4RsError::JavaError("Can't create the token".to_string()));
    }
    let out_i = jvm.create_instance("java.lang.String", &[InvocationArg::try_from(out)?]);
    Ok(out_i.unwrap())
}

#[call_from_java("org.kcramsolutions.jcerberus.TokenLib.nVerify")]
fn verify(token_i: Instance, pub_key_i: Instance) -> Result<Instance, J4RsError> {
    let jvm = Jvm::attach_thread()?;
    let null_str = "null".to_string();
    let pub_key_opt: Option<String> = jvm.to_rust(pub_key_i)?;
    let token_opt: Option<String> = jvm.to_rust(token_i)?;

    let pub_path = pub_key_opt.unwrap_or_else(|| {
        tracing::warn!("Cerberus: empty public key path");
        null_str.clone()
    });
    let token = token_opt.unwrap_or_else(|| {
        tracing::warn!("Cerberus: empty token");
        null_str.clone()
    });

    if pub_path.eq(&null_str.clone()) {
        return Err(J4RsError::JavaError("Empty Public key path".to_string()));
    }

    if token.eq(&null_str.clone()) {
        return Err(J4RsError::JavaError("Empty token".to_string()));
    }
    let public_key_pem = match std::fs::read(&pub_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("File not found! {}", e);
            return Err(J4RsError::JavaError("File not found".to_string()));
        }
    };

    let public_key = match load_public_key(&public_key_pem) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("Error loading file: {}", e);
            return Err(J4RsError::JavaError("Error loading pub key".to_string()));
        }
    };
    // Aquí debes parsear el token en "compressed_base64.signature_base64"
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        tracing::error!("Token mal formado, debe tener formato 'zip.sign'");
        return Err(J4RsError::JavaError("Token format missmatch".to_string()));
    }
    let compressed_base64 = parts[0];
    let signature_base64 = parts[1];
    let verf_result =
        match verify_signature(&public_key, compressed_base64.as_bytes(), signature_base64) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::error!("Verification error: {}", e);
                false
            }
        };
    let out_i = Instance::try_from(InvocationArg::try_from(verf_result)?);
    Ok(out_i.unwrap())
}


#[call_from_java("org.kcramsolutions.jcerberus.TokenLib.nExtractTokenData")]
fn extract_data(
    token_i: Instance,
    priv_key_i: Instance,
    encrypte_instance: Instance,
) -> Result<Instance, J4RsError> {
    let jvm = Jvm::attach_thread()?;
    let null_str = "null".to_string();
    let priv_key_opt: Option<String> = jvm.to_rust(priv_key_i)?;
    let key_path: Option<String> = jvm.to_rust(encrypte_instance)?;
    let token_opt: Option<String> = jvm.to_rust(token_i)?;

    let priv_path = priv_key_opt.unwrap_or_else(|| {
        tracing::warn!("Cerberus: empty Private key path");
        null_str.clone()
    });
    let token = token_opt.unwrap_or_else(|| {
        tracing::warn!("Cerberus: empty token");
        null_str.clone()
    });
    let rsa_path = key_path.unwrap_or_else(|| {
        tracing::error!("Cerberus: null symmetric key path!");
        null_str.clone()
    });

    if priv_path.eq(&null_str.clone()) {
        return Err(J4RsError::JavaError("Empty Public key path".to_string()));
    }

    if token.eq(&null_str.clone()) {
        return Err(J4RsError::JavaError("Empty token".to_string()));
    }

    if rsa_path.eq(&null_str.clone()) {
        return Err(J4RsError::JavaError("Empty RSA Key Path".to_string()));
    }

    let parts: Vec<&str> = token.split(".").collect();
    if parts.len() != 2 {
        tracing::error!("Malformed token");
        return Err(J4RsError::JavaError("Malformed token".to_string()));
    }
    let compressed_b64 = parts[0];
    let decompressed = match decompress_from_base64(compressed_b64) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!("Error decompressing token: {}", e);
            return Err(J4RsError::JavaError("Can't decompress token".to_string()));
        }
    };
    let inner_pars: Vec<&str> = decompressed.split(".").collect();
    if inner_pars.len() != 2 {
        tracing::error!("Malformed token");
        return Err(J4RsError::JavaError("Malformed token".to_string()));
    }
    let encrypted_header = inner_pars[0];
    let encrypted_payload = inner_pars[1];

    // Cargar clave privada
    let private_key = match load_private_key(&priv_path) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("Error cargando clave privada: {}", e);
            return Err(J4RsError::JavaError("Can't load private key".to_string()));
        }
    };

    // Desencriptar clave simétrica
    let symmetric_key = match decrypt_symmetric_key(&rsa_path, &private_key) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("Error descifrando clave simétrica: {}", e);
            return Err(J4RsError::JavaError("Can't decrypt the rsa key".to_string()));
        }
    };
    // Desencriptar header
    let header = match decrypt_from_base64(encrypted_header, &symmetric_key) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!("Error desencriptando header: {}", e);
            return Err(J4RsError::JavaError("Can't decrypt headers".to_string()));
        }
    };

    // Desencriptar payload
    let payload = match decrypt_from_base64(encrypted_payload, &symmetric_key) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!("Error desencriptando payload: {}", e);
            return Err(J4RsError::JavaError("Can't decrypt the token's body".to_string()));
        }
    };

    // Crear JSON de respuesta para simplificar entrega a Java
    let json_result = format!(r#"{{"header": {}, "payload": {}}}"#, header, payload);
    let out_i = jvm.create_instance("java.lang.String", &[InvocationArg::try_from(json_result)?]);
    match out_i{
        Ok(result) => Ok(result),
        Err(e) => {
            tracing::error!("Error devolviendo resultado: {:?}", e);
            return Err(J4RsError::JavaError("Can't write output".to_string()));
        }
    }
}

