use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::errors::error::CerberusError;
use crate::{crypto::{EncryptationConfig, utils::check_config}, errors::error::Result};


/// Encrypts data using ChaCha20-Poly1305.
///
/// Encrypts plaintext using the ChaCha20-Poly1305 authenticated encryption algorithm with the key
/// and IV from the configuration. The configuration is validated before encryption.
///
/// # Arguments
/// - `config`: Encryption configuration containing the 256-bit key and 96-bit IV (nonce)
/// - `data`: Plaintext data to encrypt
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the encrypted ciphertext with Poly1305 authentication tag
/// - `Err(CerberusError)` if configuration validation or encryption fails
///
/// # Errors
/// Returns an error if:
/// - The configuration is invalid (checked by `check_config`)
/// - The encryption operation fails
///
/// # Security
/// - Uses ChaCha20-Poly1305 which provides both confidentiality and authenticity
/// - The IV/nonce must be unique for each encryption operation with the same key
/// - Poly1305 automatically generates an authentication tag to detect tampering
/// - Configuration is validated before use to ensure key and IV are properly sized
/// - ChaCha20-Poly1305 is resistant to timing attacks and performs well on platforms without AES hardware acceleration
///
/// # Examples
/// ```
/// # use your_crate::{encrypt_chacha, EncryptationConfig};
/// # fn example(config: &EncryptationConfig) -> Result<(), Box<dyn std::error::Error>> {
/// let plaintext = b"secret message";
/// let ciphertext = encrypt_chacha(config, plaintext)?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_chacha(config: &EncryptationConfig, data: &[u8]) -> Result<Vec<u8>>{
    check_config(&config)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&config.key));
    let nonce = Nonce::from_slice(&config.iv);
    let out = cipher.encrypt(nonce, data)
        .map_err(|e| CerberusError::EncryptionError(e.to_string()))?;
    Ok(out)
}