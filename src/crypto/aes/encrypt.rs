use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};

use crate::{crypto::{EncryptationConfig, utils::check_config}, errors::error::{CerberusError, Result}};

/// Encrypts data using AES-256-GCM.
///
/// Encrypts plaintext using the AES-256-GCM authenticated encryption algorithm with the key
/// and IV from the configuration. The configuration is validated before encryption.
///
/// # Arguments
/// - `config`: Encryption configuration containing the 256-bit key and 96-bit IV (nonce)
/// - `data`: Plaintext data to encrypt
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the encrypted ciphertext with authentication tag
/// - `Err(CerberusError)` if configuration validation or encryption fails
///
/// # Errors
/// Returns an error if:
/// - The configuration is invalid (checked by `check_config`)
/// - The encryption operation fails
///
/// # Security
/// - Uses AES-256-GCM which provides both confidentiality and authenticity
/// - The IV/nonce must be unique for each encryption operation with the same key
/// - GCM mode automatically generates an authentication tag to detect tampering
/// - Configuration is validated before use to ensure key and IV are properly sized
///
/// # Examples
/// ```
/// # use your_crate::{encrypt_aes_gcm, EncryptationConfig};
/// # fn example(config: &EncryptationConfig) -> Result<(), Box<dyn std::error::Error>> {
/// let plaintext = b"secret message";
/// let ciphertext = encrypt_aes_gcm(config, plaintext)?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_aes_gcm(config: &EncryptationConfig, data: &[u8]) -> Result<Vec<u8>> {
    check_config(&config)?;
    let key = Key::<Aes256Gcm>::from_slice(&config.key);
    let nonce = Nonce::from_slice(&config.iv);
    let cipher = Aes256Gcm::new(key);
    let out = cipher.encrypt(nonce, data)
        .map_err(|e|CerberusError::EncryptionError(e.to_string()))?;
    Ok(out)
}