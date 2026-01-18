use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use crate::{crypto::{EncryptationConfig, utils::check_config}, errors::error::{CerberusError, Result}};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};




/// Decrypts data using ChaCha20-Poly1305.
///
/// Decrypts ciphertext that was encrypted using ChaCha20-Poly1305 authenticated encryption,
/// verifying the Poly1305 authentication tag to ensure the data has not been tampered with.
///
/// # Arguments
/// - `config`: Encryption configuration containing the 256-bit key and 96-bit IV (nonce)
/// - `data`: Ciphertext data to decrypt (including authentication tag)
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the decrypted plaintext
/// - `Err(CerberusError)` if configuration validation, decryption, or authentication fails
///
/// # Errors
/// Returns an error if:
/// - The configuration is invalid (checked by `check_config`)
/// - The authentication tag verification fails (data was tampered with)
/// - The key or nonce is incorrect
/// - The ciphertext is malformed or corrupted
///
/// # Security
/// - Uses ChaCha20-Poly1305 which provides both confidentiality and authenticity
/// - The Poly1305 authentication tag is automatically verified during decryption
/// - Decryption will fail if the data has been modified or if the wrong key is used
/// - The same key and IV/nonce pair must be used that were used for encryption
/// - Configuration is validated before use to ensure key and IV are properly sized
///
/// # Examples
/// ```
/// # use your_crate::{decrypt_chacha, EncryptationConfig};
/// # fn example(config: &EncryptationConfig, ciphertext: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let plaintext = decrypt_chacha(config, ciphertext)?;
/// println!("Decrypted: {:?}", plaintext);
/// # Ok(())
/// # }
/// ```
pub fn decrypt_chacha(config: &EncryptationConfig, data: &[u8]) -> Result<Vec<u8>> {
    check_config(&config)?;
    let cipher: ChaCha20Poly1305 = ChaCha20Poly1305::new(Key::from_slice(&config.key));
    let nonce = Nonce::from_slice(&config.iv);
    let out = cipher.decrypt(nonce, data)
        .map_err(|e| CerberusError::DecryptionError(e.to_string()))?;
    Ok(out)
}