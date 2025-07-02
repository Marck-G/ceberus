use core_cerberus::compression::decompress_from_base64;
use core_cerberus::crypto::{decrypt_from_base64, verify_signature};
use core_cerberus::utils::create_token;
use neon::types::Finalize;
use neon::{result::JsResult, types::JsBox};
use openssl::pkey::{PKey, Private, Public};

pub struct Cerberus{
    pub public_key_path: String,
    pub private_key_path: String,
    pub rsa_path: String,
    pub private: PKey<Private>,
    pub public: PKey<Public>,
    pub symetric: Vec<u8>,
}

impl Finalize for Cerberus{}

impl Cerberus {
    pub fn new(public_key_path: String, 
        p_key: PKey<Public>,
        p_private: PKey<Private>,
        symetric: Vec<u8>,
        private_key_path: String, 
        rsa_path: String) -> Self {
        Self { public_key_path: public_key_path, 
            private_key_path: private_key_path, 
            rsa_path: rsa_path, public: p_key, 
            private: p_private, symetric: symetric }
    }

    pub fn create(&mut self, header: String, payload: String) -> Result<String, String> {
        let token: String = create_token(&header, &payload, &self.private_key_path, &self.rsa_path)?;
        Ok(token)
    }

    pub fn verify(&mut self, token: String) -> Result<bool, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            tracing::error!("Malformed token, needed format 'zip.sign'");
                return Err("Malformed token".to_string())
        }
        let compressed_base64 = parts[0];
        let signature_base64 = parts[1];
        let verf_result: bool = verify_signature(&self.public, compressed_base64.as_bytes(), signature_base64)?;
        Ok(verf_result)
    }

    pub fn extract(&mut self, token: String) -> Result<Vec<String>, String> {
        let parts: Vec<&str> = token.split(".").collect();
        if parts.len() != 2 {
            tracing::error!("Malformed token");
            return Err("Malformed token".to_string());
        }
        let c_base64 = parts[0];
        let decompressed = match decompress_from_base64(c_base64) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Error descompressing the data: {}", e);
                return Err("Error descompressing the data".to_string());
            }
        };
        let inner_pars: Vec<&str> = decompressed.split(".").collect();
         if inner_pars.len() != 2 {
            tracing::error!("Malformed token");
            return Err("Malformed token".to_string());
        }
        let encrypted_header = inner_pars[0];
        let encrypted_payload = inner_pars[1];
        let header = match decrypt_from_base64(&encrypted_header, &self.symetric) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Error decrypting the header: {}", e);
                return Err(format!("Error decrypting the header: {}", e));
            }
        };
        let payload = match decrypt_from_base64(&encrypted_payload, &self.symetric) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Error decrypting the payload: {}", e);
                return Err(format!("Error decrypting the payload: {}", e));
            }
        };
        Ok(vec![header, payload])
    }

}