use serde::{Deserialize, Serialize};


use crate::errors::error::{CerberusError, Result};

/// Supported encryption algorithms for the Cerberus protocol.
///
/// This enum defines the available authenticated encryption algorithms that can be used
/// for securing message payloads. All algorithms provide both confidentiality and integrity
/// through Authenticated Encryption with Associated Data (AEAD).
///
/// # Variants
///
/// * `Aes256Gcm` - AES-256 in Galois/Counter Mode
///   - 256-bit key, 96-bit nonce
///   - Best performance on platforms with AES-NI hardware acceleration
///   - NIST-approved and widely supported
///
/// * `ChaCha20Poly1305` - ChaCha20 stream cipher with Poly1305 MAC
///   - 256-bit key, 96-bit nonce
///   - Best performance on platforms without hardware acceleration
///   - Resistant to timing attacks
///   - Recommended by RFC 8439
///
/// # Security
/// Both algorithms are considered secure and provide equivalent security levels (256-bit).
/// The choice between them typically depends on hardware capabilities and performance requirements.
///
/// # Examples
/// ```
/// # use your_crate::EncryptionType;
/// let algo = EncryptionType::Aes256Gcm;
/// // Use in configuration
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptionType {
    Aes256Gcm,
    ChaCha20Poly1305,
    // Aes256Cbc, (si lo necesitas luego)
}

/// Configuration for encryption operations in the Cerberus protocol.
///
/// This structure contains all necessary parameters for symmetric encryption and decryption,
/// including the algorithm choice, encryption key, and initialization vector (IV/nonce).
///
/// # Fields
///
/// * `algo` - The encryption algorithm to use (AES-256-GCM or ChaCha20-Poly1305)
/// * `key` - The symmetric encryption key (must be 32 bytes for 256-bit security)
/// * `iv` - The initialization vector/nonce (must be 12 bytes/96 bits for both supported algorithms)
///
/// # Security Requirements
///
/// - **Key**: Must be 32 bytes (256 bits) and generated using a cryptographically secure random number generator
/// - **IV/Nonce**: Must be 12 bytes (96 bits) and must be unique for each encryption operation with the same key
/// - **IV Reuse**: Never reuse the same IV with the same key, as this catastrophically breaks security
///
/// # Validation
///
/// The configuration should be validated using `check_config()` before use to ensure
/// the key and IV have the correct lengths for the selected algorithm.
///
/// # Examples
/// ```
/// # use your_crate::{EncryptationConfig, EncryptionType};
/// # fn example() {
/// let config = EncryptationConfig {
///     algo: EncryptionType::Aes256Gcm,
///     key: vec![0u8; 32],  // In practice, use a secure random key
///     iv: vec![0u8; 12],   // In practice, use a unique random nonce
/// };
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct EncryptationConfig {
    pub algo: EncryptionType,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
}

/// Validates an encryption configuration to ensure it meets security requirements.
///
/// This function checks that the key and IV lengths are correct for the AEAD algorithms
/// supported by the Cerberus protocol. Both AES-256-GCM and ChaCha20-Poly1305 require
/// 256-bit keys and 96-bit nonces.
///
/// # Arguments
/// - `config`: The encryption configuration to validate
///
/// # Returns
/// - `Ok(())` if the configuration is valid
/// - `Err(CerberusError::KeyLengthError)` if the key is not 32 bytes
/// - `Err(CerberusError::IVLengthError)` if the IV is not 12 bytes
///
/// # Validation Rules
/// - **Key length**: Must be exactly 32 bytes (256 bits)
/// - **IV length**: Must be exactly 12 bytes (96 bits)
///
/// # Examples
/// ```
/// # use your_crate::{check_config, EncryptationConfig, EncryptionType};
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = EncryptationConfig {
///     algo: EncryptionType::Aes256Gcm,
///     key: vec![0u8; 32],
///     iv: vec![0u8; 12],
/// };
///
/// check_config(&config)?;  // Returns Ok(())
/// # Ok(())
/// # }
/// ```
///
/// # Note
/// This function should be called before performing any encryption or decryption operations
/// to catch configuration errors early.
pub fn check_config(config: &EncryptationConfig) -> Result<()> {
    if config.key.len() != 32 {
        return Err(CerberusError::KeyLenghtError(32));
    }
    if config.iv.len() != 12 {
        return Err(CerberusError::IVLenghtError(12));

    }

    Ok(())
}