use openssl::{hash::MessageDigest, pkey::{self, PKey}, sign::{Signer, Verifier}};

use crate::errors::error::{CerberusError, Result};

/// Signs an arbitrary message using a private key and SHA3-512.
///
/// This function computes a cryptographic signature over the provided `data`
/// using the given private key and the SHA3-512 message digest. The resulting
/// signature can later be verified using the corresponding public key.
///
/// # Parameters
/// - `private_key`: A reference to an OpenSSL private key used for signing.
///   The key must be compatible with the selected message digest.
/// - `data`: The message or binary data to be signed.
///
/// # Returns
/// - `Ok(Vec<u8>)`: The generated signature as raw bytes.
/// - `Err(CerberusError)`: If the signing operation fails at any stage
///   (initialization, update, or finalization).
///
/// # Errors
/// This function returns a `CerberusError::SignError` if:
/// - The signer cannot be initialized with the provided key
/// - The input data cannot be processed
/// - The signature generation fails
///
/// # Cryptographic Notes
/// - Uses **SHA3-512** as the message digest algorithm.
/// - The signature algorithm depends on the type of the provided private key
///   (e.g. RSA, ECDSA, Ed25519).
/// - The signature is deterministic or randomized depending on the key type
///   and OpenSSL implementation.
///
/// # Security Considerations
/// - The private key must be kept secret and securely stored.
/// - Do not reuse this function for untrusted or user-controlled private keys.
/// - Ensure the corresponding public key is distributed securely for
///   verification.
///
/// # Example
/// ```rust
/// use openssl::pkey::PKey;
///
/// let data = b"important message";
/// let signature = sign_message(&private_key, data)?;
/// ```
///
/// # See Also
/// - [`openssl::sign::Signer`]
/// - [`openssl::hash::MessageDigest::sha3_512`]
pub fn sign_message(private_key: &PKey<pkey::Private>, data: &[u8]) -> Result<Vec<u8>> {
    let mut signer = Signer::new(MessageDigest::sha3_512(), private_key)
        .map_err(|e| CerberusError::SignError(e.to_string()))?;
    signer.update(data)
        .map_err(|e| CerberusError::SignError(e.to_string()))?;
    let signature = signer.sign_to_vec()
        .map_err(|e| CerberusError::SignError(e.to_string()))?;
    Ok(signature)
}

/// Verifies a cryptographic signature against the provided data and public key.
///
/// This function checks whether `signature` is a valid signature for the given
/// `data`, using the provided public key and the SHA3-512 message digest.
/// It returns `true` if the signature is valid, or `false` if it is not.
///
/// # Parameters
/// - `public_key`: A reference to the public key corresponding to the private
///   key used for signing.
/// - `data`: The original message or binary data that was signed.
/// - `signature`: The signature bytes to be verified.
///
/// # Returns
/// - `Ok(true)`: The signature is valid.
/// - `Ok(false)`: The signature is invalid.
/// - `Err(CerberusError)`: If the verification process fails due to an internal
///   error (e.g. invalid key, OpenSSL failure).
///
/// # Errors
/// Returns `CerberusError::SignError` if:
/// - The verifier cannot be initialized
/// - The input data cannot be processed
/// - The verification operation fails
///
/// # Cryptographic Notes
/// - Uses **SHA3-512** as the message digest.
/// - The verification algorithm depends on the public key type
///   (RSA, ECDSA, Ed25519, etc.).
///
/// # Example
/// ```rust
/// let is_valid = check_sign(&public_key, data, &signature)?;
/// assert!(is_valid);
/// ```
pub fn check_sign(
    public_key: &PKey<pkey::Public>,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let mut verifier = Verifier::new(MessageDigest::sha3_512(), public_key)
        .map_err(|e| CerberusError::SignError(e.to_string()))?;

    verifier.update(data)
        .map_err(|e| CerberusError::SignError(e.to_string()))?;

    let is_valid = verifier
        .verify(signature)
        .map_err(|e| CerberusError::SignError(e.to_string()))?;

    Ok(is_valid)
}