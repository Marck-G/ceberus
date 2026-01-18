use crate::crypto::{aes, chacha};
use crate::{crypto::EncryptationConfig, errors::error::Result};


/// Encrypts data using the algorithm specified in the configuration.
///
/// This is a convenience function that dispatches to the appropriate encryption implementation
/// based on the encryption algorithm specified in the configuration (AES-256-GCM or ChaCha20-Poly1305).
///
/// # Arguments
/// - `config`: Encryption configuration specifying the algorithm, key, and IV (nonce)
/// - `data`: Plaintext data to encrypt
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the encrypted ciphertext with authentication tag
/// - `Err(CerberusError)` if configuration validation or encryption fails
///
/// # Errors
/// Returns an error if:
/// - The configuration is invalid
/// - The encryption operation fails
///
/// # Supported Algorithms
/// - `Aes256Gcm`: Uses AES-256 in Galois/Counter Mode (preferred on platforms with AES-NI)
/// - `ChaCha20Poly1305`: Uses ChaCha20 stream cipher with Poly1305 MAC (preferred on platforms without hardware acceleration)
///
/// # Security
/// Both algorithms provide authenticated encryption (AEAD), ensuring confidentiality and integrity.
/// The IV/nonce must be unique for each encryption operation with the same key.
///
/// # Examples
/// ```
/// # use your_crate::{encrypt, EncryptationConfig, EncryptionType};
/// # fn example(config: &EncryptationConfig) -> Result<(), Box<dyn std::error::Error>> {
/// let plaintext = b"secret message";
/// let ciphertext = encrypt(config, plaintext)?;
/// println!("Encrypted {} bytes", ciphertext.len());
/// # Ok(())
/// # }
/// ```
pub fn encrypt(config: &EncryptationConfig, data: &[u8]) -> Result<Vec<u8>> {
    match config.algo {
        super::EncryptionType::Aes256Gcm => {
            return aes::encrypt_aes_gcm(&config, data);
        },
        super::EncryptionType::ChaCha20Poly1305 => {
            return chacha::encrypt_chacha(&config, data);
        }
    }
}