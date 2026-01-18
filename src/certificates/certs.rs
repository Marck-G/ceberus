use std::fs;
use openssl::{pkey::{PKey, Private, Public}, rsa::Rsa};

use crate::errors::error::{CerberusError, Result};

/// Load **private key** from file path\
/// \
/// #### Arguments
/// **`key_path`**: _String_ = the private kew _pem_ file
/// ### Example
/// ```rust
/// use openssl::pkey::Private;
///
/// let path: String = String::new("/usr/shared/certificates/owner_priv.pem");
/// let private_key: Private = load_private_key_fs(path).unwrap();
///
/// ```
pub fn load_private_key_fs(key_path: String) -> Result<PKey<Private>> {
    let key_data: Vec<u8> = fs::read(key_path.as_str())
        .map_err(|_|  CerberusError::KeyReadError(key_path.to_owned()))?;
    let key_processed: Rsa<Private> = Rsa::private_key_from_pem(&key_data)
        .map_err(|_| CerberusError::KeyParseError(key_path.to_owned()))?;
    let private_key: PKey<Private> = PKey::from_rsa(key_processed)
        .map_err(|_| CerberusError::KeyFormatError(key_path.to_owned()))?;
    Ok(private_key)
}

/// Load **public key** from file path\
/// \
/// #### Arguments
/// **`key_path`**: _String_ = the public kew _pem_ file
/// ### Example
/// ```rust
/// use openssl::pkey::Public;
///
/// let path: String = String::new("/usr/shared/certificates/owner_priv.pem");
/// let public: Public = load_public_key_fs(path).unwrap();
///
/// ```
pub fn load_public_key_fs(key_path: String) -> Result<PKey<Public>> {
    let key_bytes: Vec<u8> = fs::read(key_path.as_str())
    .map_err(|_| CerberusError::KeyReadError(key_path.to_owned()))?;
    let public: PKey<Public> = load_public_key(&key_bytes)
        .map_err(|_| CerberusError::KeyFormatError(key_path.to_owned()))?;
    Ok(public)
}


/// Load **public key** from raw binary array \
/// \
/// #### Arguments
/// **`bytes`**: _&\[u8\]_ = the public kew raw data
/// ### Example
/// ```rust
/// use openssl::pkey::Public;
/// use std:fs;
///
/// let bytes: Vec<u8> = fs::read("/usr/shared/certificates/owner_priv.pem");
/// let public: Public = load_public_key(bytes).unwrap();
///
/// ```
pub fn load_public_key(bytes: &[u8]) -> Result<PKey<Public>> {
    let public_key: PKey<Public> = PKey::public_key_from_pem(&bytes)
        .map_err(|_| CerberusError::KeyBinaryError)?;
    Ok(public_key)
}


/// Load **private key** from raw binary array \
/// \
/// #### Arguments
/// **`bytes`**: _&\[u8\]_ = the private kew raw data
/// ### Example
/// ```rust
/// use openssl::pkey::private;
/// use std:fs;
///
/// let bytes: Vec<u8> = fs::read("/usr/shared/certificates/owner_priv.pem");
/// let private: private = load_private_key(bytes).unwrap();
///
/// ```
pub fn load_private_key(bytes: &[u8]) -> Result<PKey<Private>> {
    let private_rsa_key: Rsa<Private> = Rsa::private_key_from_pem(&bytes)
        .map_err(|_| CerberusError::KeyReadError("Binary Load".into()))?;
    let private_key: PKey<Private> = PKey::from_rsa(private_rsa_key)
        .map_err(|_| CerberusError::KeyFormatError("Binary Load".into()))?;
    Ok(private_key)
}