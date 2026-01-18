
use zstd::{decode_all, encode_all};


use crate::errors::error::{CerberusError, Result};


/// Default Zstandard compression level used by the library.
///
/// A value of `15` provides a good balance between compression ratio
/// and CPU usage, and is suitable for compressing binaries or large
/// payloads before encryption.
const COMPRESSION_LEVEL: i32 = 15;


/// Compresses binary data using the Zstandard (zstd) algorithm.
///
/// This function compresses the provided binary data using Zstandard
/// with a predefined compression level. It is designed to be used
/// **before encryption** to reduce payload size while preserving
/// cryptographic security.
///
/// # Parameters
/// - `data`: A byte slice containing the raw binary data to be compressed.
///
/// # Returns
/// - `Ok(Vec<u8>)`: The compressed binary data.
/// - `Err(CerberusError)`: If the compression process fails.
///
/// # Errors
/// Returns `CerberusError::CodificationError` if:
/// - The Zstandard encoder fails
/// - The input data cannot be processed
///
/// # Compression Details
/// - Algorithm: **Zstandard (zstd)**
/// - Compression level: `15`
/// - Output format: Zstandard frame format
///
/// # Security Notes
/// - Always compress **before** encrypting.
/// - Compressed data is not encrypted or authenticated by itself.
/// - Do not assume compressed data is safe to process from untrusted
///   sources without verification.
///
/// # Example
/// ```rust
/// let original = b"repetitive repetitive repetitive data";
/// let compressed = compress(original).unwrap();
/// assert!(compressed.len() < original.len());
/// ```
pub fn compress(data: &[u8]) -> Result<Vec<u8>>{
    encode_all(data, COMPRESSION_LEVEL)
        .map_err(|e| CerberusError::CodificationError(e.to_string()))
}


/// Decompresses Zstandard-compressed binary data.
///
/// This function restores the original binary data from Zstandard-
/// compressed input. It must be applied **after decryption** if the
/// data was previously compressed and encrypted.
///
/// # Parameters
/// - `data`: A byte slice containing Zstandard-compressed data.
///
/// # Returns
/// - `Ok(Vec<u8>)`: The decompressed original binary data.
/// - `Err(CerberusError)`: If the decompression process fails.
///
/// # Errors
/// Returns `CerberusError::CodificationError` if:
/// - The input data is not valid Zstandard format
/// - The decompression fails or the data is corrupted
///
/// # Security Notes
/// - Never decompress untrusted data without size limits (risk of
///   decompression bombs).
/// - Always verify integrity (signature or AEAD) **before** calling
///   this function.
///
/// # Example
/// ```rust
/// let compressed = compress(b"hello").unwrap();
/// let original = decompress(&compressed).unwrap();
/// assert_eq!(original, b"hello");
/// ```
pub fn decompress(data: &[u8]) -> Result<Vec<u8>>{
    decode_all(data)
        .map_err(|e| CerberusError::CodificationError(e.to_string()))
}