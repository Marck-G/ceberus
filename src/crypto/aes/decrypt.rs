use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead};

use crate::{crypto::EncryptationConfig, errors::error::{CerberusError, Result}};

/// Decrypts data using AES-256-GCM.
///
/// Decrypts ciphertext that was encrypted using AES-256-GCM authenticated encryption,
/// verifying the authentication tag to ensure the data has not been tampered with.
///
/// # Arguments
/// - `config`: Encryption configuration containing the 256-bit key and 96-bit IV (nonce)
/// - `data`: Ciphertext data to decrypt (including authentication tag)
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the decrypted plaintext
/// - `Err(CerberusError::EncryptionError)` if decryption or authentication fails
///
/// # Errors
/// Returns an error if:
/// - The authentication tag verification fails (data was tampered with)
/// - The key or nonce is incorrect
/// - The ciphertext is malformed or corrupted
///
/// # Security
/// - Uses AES-256-GCM which provides both confidentiality and authenticity
/// - The authentication tag is automatically verified during decryption
/// - Decryption will fail if the data has been modified or if the wrong key is used
/// - The same key and IV/nonce pair must be used that were used for encryption
///
/// # Examples
/// ```
/// # use your_crate::{decryp_aes_gcm, EncryptationConfig};
/// # fn example(config: &EncryptationConfig, ciphertext: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let plaintext = decryp_aes_gcm(config, ciphertext)?;
/// println!("Decrypted: {:?}", plaintext);
/// # Ok(())
/// # }
/// ```
pub fn decryp_aes_gcm(config: &EncryptationConfig, data: &[u8]) -> Result<Vec<u8>> {
     let key = Key::<Aes256Gcm>::from_slice(&config.key);
    let nonce = Nonce::from_slice(&config.iv);
    let cipher = Aes256Gcm::new(key);
    let out = cipher.decrypt(nonce, data)
        .map_err(|e|CerberusError::EncryptionError(e.to_string()))?;
    Ok(out)
}