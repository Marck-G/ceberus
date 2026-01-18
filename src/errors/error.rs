use std::{error::Error, fmt::Display};


/// Error types for the Cerberus protocol operations.
///
/// This enum encompasses all possible errors that can occur during cryptographic operations,
/// key management, message encoding/decoding, and protocol execution.
///
/// # Variants
///
/// * `KeyReadError(String)` - Failed to read a cryptographic key from storage or input
///   - Contains details about the read failure
///
/// * `KeyParseError(String)` - Failed to parse a key from its serialized format
///   - Contains details about the parsing failure
///
/// * `KeyFormatError(String)` - Key is in an incorrect or unsupported format
///   - Contains details about the format issue
///
/// * `KeyBinaryError` - Error converting key to/from binary representation
///
/// * `KeyLengthError(i64)` - Cryptographic key has incorrect length
///   - Contains the expected key length in bytes
///
/// * `IVLengthError(i64)` - Initialization vector (IV/nonce) has incorrect length
///   - Contains the expected IV length in bytes
///
/// * `EncryptionError(String)` - Encryption operation failed
///   - Contains details about the encryption failure
///
/// * `DecryptionError(String)` - Decryption or authentication verification failed
///   - Contains details about the decryption failure
///   - May indicate tampered data if authentication tag verification fails
///
/// * `CodificationError(String)` - Error encoding or decoding message structure
///   - Contains details about the serialization/deserialization failure
///
/// * `SignError(String)` - Digital signature creation or verification failed
///   - Contains details about the signature operation failure
///
/// * `MessageLengthError(String)` - Message has invalid or unexpected length
///   - Contains details about the length issue
///
/// # Examples
/// ```
/// # use your_crate::CerberusError;
/// # fn example() -> Result<(), CerberusError> {
/// let key = vec![0u8; 16];  // Wrong size
/// if key.len() != 32 {
///     return Err(CerberusError::KeyLengthError(32));
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub enum CerberusError {
    KeyReadError(String), // Error reading the key
    KeyParseError(String),
    KeyFormatError(String),
    KeyBinaryError,
    KeyLenghtError(i64),
    IVLenghtError(i64),
    EncryptionError(String),
    DecryptionError(String),
    CodificationError(String),
    SignError(String),
    MessageLengthError(String),
}


impl Display for CerberusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CerberusError::KeyFormatError(file) => write!(f, "Error with the key's format. Key file: {file}"),
            CerberusError::KeyParseError(file) => write!(f, "Error while parsing key's file {file}"),
            CerberusError::KeyReadError(file) => write!(f, "Error while reading the key's file {file}"),
            CerberusError::KeyBinaryError => write!(f, "Error while reading key raw binary"),
            CerberusError::EncryptionError(msg) => write!(f, "Can't encrypt data: {msg}"),
            CerberusError::DecryptionError(msg) => write!(f, "Can't decrypt data: {msg}"),
            CerberusError::KeyLenghtError(length) => write!(f, "Wrong key length, require size {length}"),
            CerberusError::IVLenghtError(length) => write!(f, "Wrong IV length, require size {length}"),
            CerberusError::CodificationError(msg) => write!(f, "Error while encoding/decoding Base64: {msg}"),
            CerberusError::SignError(msg)=> write!(f, "Error while sign message: {msg}"),
            CerberusError::MessageLengthError(msg)=> write!(f, "Error with length: {msg}"),
        }
    }

}

impl Error for CerberusError {}

pub type Result<T> = std::result::Result<T, CerberusError>;