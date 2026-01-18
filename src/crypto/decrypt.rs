use crate::{crypto::{EncryptationConfig, aes, chacha}, errors::error::Result};


/// Decrypts data using the algorithm specified in the configuration.
///
/// This is a convenience function that dispatches to the appropriate decryption implementation
/// based on the encryption algorithm specified in the configuration (ChaCha20-Poly1305 or AES-256-GCM).
///
/// # Arguments
/// - `config`: Encryption configuration specifying the algorithm, key, and IV (nonce)
/// - `data`: Ciphertext data to decrypt (including authentication tag)
///
/// # Returns
/// - `Ok(Vec<u8>)` containing the decrypted plaintext
/// - `Err(CerberusError)` if decryption or authentication fails
///
/// # Errors
/// Returns an error if:
/// - The configuration is invalid
/// - The authentication tag verification fails (data was tampered with)
/// - The key or nonce is incorrect
/// - The ciphertext is malformed or corrupted
///
/// # Supported Algorithms
/// - `ChaCha20Poly1305`: Uses ChaCha20 stream cipher with Poly1305 MAC
/// - `Aes256Gcm`: Uses AES-256 in Galois/Counter Mode
///
/// # Examples
/// ```
/// # use your_crate::{decrypt, EncryptationConfig, EncryptionType};
/// # fn example(config: &EncryptationConfig, ciphertext: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
/// let plaintext = decrypt(config, ciphertext)?;
/// println!("Decrypted {} bytes", plaintext.len());
/// # Ok(())
/// # }
/// ```
pub fn decrypt(config: &EncryptationConfig, data: &[u8]) ->Result<Vec<u8>>{
    match config.algo {
        super::EncryptionType::ChaCha20Poly1305 => {
            return chacha::decrypt_chacha(&config, data);
        },
        super::EncryptionType::Aes256Gcm => {
            return aes::decryp_aes_gcm(&config, data);
        }
    }
}

