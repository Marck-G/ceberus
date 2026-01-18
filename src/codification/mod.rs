// codification module

use base64::{Engine, engine::general_purpose};


use crate::errors::error::{CerberusError, Result};


/// Encodes arbitrary binary data into a Base64 string.
///
/// This function converts raw binary data into a Base64-encoded `String`
/// using the standard Base64 alphabet (RFC 4648).
///
/// # Parameters
/// - `data`: A byte slice containing the binary data to encode.
///
/// # Returns
/// - A `String` containing the Base64 representation of the input data.
///
/// # Notes
/// - The output is ASCII-safe and suitable for text-based formats
///   (JSON, XML, headers, etc.).
/// - No line wrapping is applied.
///
/// # Example
/// ```rust
/// let encoded = to_base64(b"hello");
/// assert_eq!(encoded, "aGVsbG8=");
/// ```
pub fn to_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}



/// Decodes a Base64-encoded string into raw binary data.
///
/// This function accepts any type that can be referenced as a string,
/// decodes it using the standard Base64 alphabet, and returns the
/// original binary data.
///
/// # Parameters
/// - `data`: A Base64-encoded string (`&str`, `String`, etc.).
///
/// # Returns
/// - `Ok(Vec<u8>)`: The decoded binary data.
/// - `Err(CerberusError)`: If the input is not valid Base64.
///
/// # Errors
/// Returns `CerberusError::CodificationError` if:
/// - The input string contains invalid Base64 characters
/// - The input length is invalid
///
/// # Security Notes
/// - This function does **not** perform any validation on the decoded
///   data beyond Base64 correctness.
/// - Always validate or authenticate decoded data if it comes from
///   an untrusted source.
///
/// # Example
/// ```rust
/// let decoded = from_base64_string("aGVsbG8=").unwrap();
/// assert_eq!(decoded, b"hello");
/// ```
pub fn from_base64_string<T: AsRef<str>>(data:T) -> Result<Vec<u8>> {
    general_purpose::STANDARD.decode(data.as_ref().as_bytes())
    .map_err(|e| CerberusError::CodificationError(e.to_string()))
}


/// Decodes Base64-encoded data provided as raw bytes.
///
/// This function is useful when the Base64 input is already available
/// as a byte slice rather than a UTF-8 string (e.g. data read from a file
/// or network buffer).
///
/// # Parameters
/// - `data`: A byte slice containing Base64-encoded data.
///
/// # Returns
/// - `Ok(Vec<u8>)`: The decoded binary data.
/// - `Err(CerberusError)`: If the input is not valid Base64.
///
/// # Errors
/// Returns `CerberusError::CodificationError` if:
/// - The input contains invalid Base64 data
/// - The decoding process fails
///
/// # Notes
/// - The input does not need to be valid UTF-8.
/// - Uses the standard Base64 alphabet (RFC 4648).
///
/// # Example
/// ```rust
/// let input = b"aGVsbG8=";
/// let decoded = from_base64(input).unwrap();
/// assert_eq!(decoded, b"hello");
/// ```
pub fn from_base64(data:&[u8]) -> Result<Vec<u8>> {
    general_purpose::STANDARD.decode(&data)
    .map_err(|e| CerberusError::CodificationError(e.to_string()))
}