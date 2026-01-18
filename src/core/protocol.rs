use std::io::Write;

use openssl::pkey::{PKey, Private, Public};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    certificates::{check_sign, sign_message},
    compresion::{compress, decompress},
    core::handsake_sesion::HandshakeSession,
    crypto::{EncryptationConfig, EncryptionType, decrypt, encrypt},
    errors::error::{CerberusError, Result},
};

/// A secure communication protocol that provides encryption, compression, and signing for messages.
///
/// `CerberusProtocol` implements end-to-end encrypted communication between two parties using
/// asymmetric cryptography. It combines encryption, compression, and digital signatures to ensure
/// confidentiality, integrity, and authenticity of messages.
///
/// # Fields
/// - `target`: The peer's public key, used to encrypt outgoing messages
/// - `source`: The agent's private key, used to sign outgoing messages and decrypt incoming messages
/// - `config`: Encryption configuration specifying the algorithm, symmetric key, and IV
///
/// # Security Model
/// - **Confidentiality**: Messages are encrypted using the configuration's symmetric cipher
/// - **Integrity**: All messages are signed using SHA3-256 with the source private key
/// - **Authenticity**: Signatures verify the sender's identity
/// - **Compression**: Payloads are compressed before encryption to reduce size and obscure patterns
///
/// # Usage
/// The protocol supports two modes of operation:
/// - **Basic mode**: `encode_message`/`decode_message` for signed but unencrypted messages
/// - **Secure mode**: `secure_encode`/`secure_decode` for compressed, encrypted, and signed messages
///
/// # Examples
/// ```
/// # use your_crate::{CerberusProtocol, EncryptionConfig};
/// # use openssl::pkey::{PKey, Private, Public};
/// # use serde_json::json;
/// # fn example(config: EncryptionConfig, peer_public: PKey<Public>, my_private: PKey<Private>) -> Result<(), Box<dyn std::error::Error>> {
/// // Create a protocol instance
/// let protocol = CerberusProtocol::new(config, peer_public, my_private);
///
/// // Send a secure message
/// let header = json!({"type": "greeting", "timestamp": 12345});
/// let body = b"Hello, peer!";
/// let encrypted = protocol.secure_encode(&header, body)?;
///
/// // Receive and decrypt a message
/// let decoded = protocol.secure_decode(&encrypted)?;
/// # Ok(())
/// # }
/// ```
#[allow(dead_code)]
pub struct CerberusProtocol {
    target: PKey<Public>,
    source: PKey<Private>,
    config: EncryptationConfig,
}

/// Representa un mensaje decodificado de CerberusProtocol.
///
/// Contiene:
/// - `header`: bytes JSON del header del mensaje
/// - `body`: payload binario
/// - `sign`: firma digital que asegura integridad y autenticidad
#[derive(Debug, Serialize, Deserialize)]
pub struct BasicMessage {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
    pub sign: Vec<u8>,
}

#[allow(dead_code)]
impl CerberusProtocol {
    /// Creates a new secure protocol instance with the agent's private key and the peer's public key.
    ///
    /// # Arguments
    /// - `config`: Encryption configuration (algorithm, key, initial IV)
    /// - `target_public`: Peer's public key used to encrypt messages
    /// - `owner_private`: Agent's private key used to sign messages
    ///
    /// # Returns
    /// A `CerberusProtocol` instance initialized and ready to send encrypted messages.
    ///
    /// # Security
    /// - The private key must be kept secure and never shared.
    /// - The target public key must be verified during handshake to prevent MITM attacks.
    ///
    /// # Examples
    /// ```
    /// # use your_crate::{CerberusProtocol, EncryptionConfig};
    /// # use openssl::pkey::{PKey, Private, Public};
    /// # fn example(config: EncryptionConfig, peer_public: PKey<Public>, my_private: PKey<Private>) {
    /// let protocol = CerberusProtocol::new(config, peer_public, my_private);
    /// # }
    /// ```
    pub fn new(
        config: &EncryptationConfig,
        target_public: &PKey<Public>,
        owner_private: &PKey<Private>,
    ) -> Self {
        Self {
            target: target_public.clone(),
            source: owner_private.clone(),
            config: config.clone(),
        }
    }

    /// Creates a protocol instance from a completed handshake session.
    ///
    /// This allows initializing the protocol using the peer's public key and the IV agreed upon
    /// during the handshake, leaving the protocol ready to encrypt and sign messages.
    ///
    /// # Arguments
    /// - `session`: Completed handshake session (must have target and IV defined)
    /// - `owner_private`: The agent's private key
    ///
    /// # Returns
    /// - `Ok(CerberusProtocol)` if the session is complete
    /// - `Err(CerberusError)` if the session doesn't have a defined target or IV
    ///
    /// # Safety
    /// - Must only be called after completing the handshake.
    /// - The IV is set from the session and is used in all subsequent encrypted messages.
    ///
    /// # Examples
    /// ```
    /// # use your_crate::{CerberusProtocol, HandshakeSession};
    /// # use openssl::pkey::{PKey, Private};
    /// # fn example(session: HandshakeSession, private_key: PKey<Private>) -> Result<(), Box<dyn std::error::Error>> {
    /// let protocol = CerberusProtocol::from_session(&session, &private_key)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_session(session: &HandshakeSession, owner_private: &PKey<Private>) -> Result<Self> {
        // Verificar que la sesión tiene target público y IV configurados
        let target = session.target.as_ref().ok_or(CerberusError::KeyReadError(
            "Handshake session has no target public key".into(),
        ))?;

        if session.iv.is_none() {
            return Err(CerberusError::KeyFormatError(
                "Handshake session has no IV set".into(),
            ));
        }

        let config = EncryptationConfig {
            iv: session.iv.unwrap().to_vec(), // asignamos IV de la sesión
            algo: session.algo.clone(),
            key: session.symmetric_key.clone().unwrap(),
        };
        Ok(Self {
            target: target.clone(),
            source: owner_private.clone(),
            config,
        })
    }

    /// Encodes a plain message by combining a JSON header and binary payload, then signs it.
    ///
    /// The final message format is:
    /// `[HEADER_LEN: 4 bytes][HEADER_JSON][BINARY_BODY][SIGNATURE]`
    ///
    /// # Arguments
    /// - `header`: Reference to a JSON value representing the message header
    /// - `body`: Binary payload of the message
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` with the complete encoded and signed message
    /// - `Err(CerberusError)` if the message is too short, or the signature is invalid
    ///
    /// # Security
    /// - Uses SHA3-256 for signing with the `source` private key.
    /// - The signature covers both header and body to ensure integrity and authenticity.
    /// - Does not modify the session's encryption configuration.
    ///
    /// # Examples
    /// ```
    /// # use your_crate::CerberusProtocol;
    /// # use serde_json::json;
    /// # fn example(protocol: &CerberusProtocol) -> Result<(), Box<dyn std::error::Error>> {
    /// let header = json!({"type": "message", "timestamp": 12345});
    /// let body = b"encrypted payload";
    /// let encoded = protocol.encode_message(&header, body)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn encode_message(&self, header: &serde_json::Value, body: &[u8]) -> Result<Vec<u8>> {
        let mut block = Vec::new();

        // Serializar header JSON
        let header_bytes = serde_json::to_vec(header)
            .map_err(|_| CerberusError::CodificationError("Failed to serialize header".into()))?;

        let header_len = header_bytes.len() as u32;

        // Escribir header length (4 bytes, big-endian)
        block
            .write_all(&header_len.to_be_bytes())
            .map_err(|e| CerberusError::CodificationError(e.to_string()))?;

        // Escribir header y payload
        block
            .write_all(&header_bytes)
            .map_err(|e| CerberusError::CodificationError(e.to_string()))?;
        block
            .write_all(body)
            .map_err(|e| CerberusError::CodificationError(e.to_string()))?;

        // Firmar SHA3-256 sobre [header_len + header + body]
        let signature = sign_message(&self.source, &block)?;

        // Añadir firma al final
        block
            .write_all(&signature)
            .map_err(|e| CerberusError::CodificationError(e.to_string()))?;

        Ok(block)
    }

    /// Decodes a plain message and verifies its signature.
    ///
    /// Expects the message to have the format `[HEADER_LEN:4][HEADER_JSON][BODY][SIGNATURE]`.
    /// The signature is verified using the agent's private key (in this design, could be replaced
    /// with the peer's public key depending on requirements).
    ///
    /// # Arguments
    /// - `msg`: Byte slice containing the complete message
    ///
    /// # Returns
    /// - `Ok(BasicMessage)` with the three components: `header`, `body`, and `sign`
    /// - `Err(CerberusError)` if the message is too short or the signature is invalid
    ///
    /// # Errors
    /// Returns an error if:
    /// - The message is malformed or too short to contain all required components
    /// - The signature verification fails
    /// - The header JSON cannot be parsed
    ///
    /// # Security
    /// - Ensures the message has not been tampered with and originates from an authorized agent.
    /// - Uses SHA3-256 to verify integrity.
    /// - The signature covers both header and payload.
    ///
    /// # Examples
    /// ```
    /// # use your_crate::CerberusProtocol;
    /// # fn example(protocol: &CerberusProtocol, encoded_msg: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let decoded = protocol.decode_message(encoded_msg)?;
    /// println!("Header: {:?}", decoded.header);
    /// println!("Body length: {}", decoded.body.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode_message(&self, msg: &[u8]) -> Result<BasicMessage> {
        // 1️⃣ Comprobar tamaño mínimo: 4 bytes header_len + firma
        if msg.len() < 4 {
            return Err(CerberusError::MessageLengthError(
                "Wrong message length for decode".into(),
            ));
        }

        // Leer header length
        let header_len = u32::from_be_bytes(msg[..4].try_into().unwrap()) as usize;

        // Comprobar que hay suficientes bytes para header + firma
        if msg.len() < 4 + header_len {
            return Err(CerberusError::MessageLengthError(
                "Message too short for header".into(),
            ));
        }

        // Determinar donde empieza la firma
        // Suponemos que la firma tiene longitud igual a la clave privada usada (RSA)
        let rsa_size = self.source.rsa().unwrap().size() as usize;
        if msg.len() < 4 + header_len + rsa_size {
            return Err(CerberusError::MessageLengthError(
                "Message too short for signature".into(),
            ));
        }

        let header_bytes = &msg[4..4 + header_len];
        let body_bytes = &msg[4 + header_len..msg.len() - rsa_size];
        let signature_bytes = &msg[msg.len() - rsa_size..];
        // Verificar firma sobre [header_len + header + body]
        let signed_data = &msg[..msg.len() - rsa_size];
        let is_valid = check_sign(&self.target, signed_data, signature_bytes)?;
        info!("Verification: {}", is_valid);
        if !is_valid {
            return Err(CerberusError::SignError(
                "Signature verification failed".into(),
            ));
        }

        // Devolver estructura BasicMessage
        Ok(BasicMessage {
            header: header_bytes.to_vec(),
            body: body_bytes.to_vec(),
            sign: signature_bytes.to_vec(),
        })
    }

    /// Creates an encrypted and compressed message.
    ///
    /// This method processes the message through compression and encryption before encoding,
    /// providing confidentiality in addition to the integrity guarantees of standard encoding.
    ///
    /// # Arguments
    /// - `header`: Reference to a JSON value representing the message header
    /// - `body`: Binary payload of the message to be compressed and encrypted
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)` with the complete compressed, encrypted, and encoded message
    /// - `Err(CerberusError)` if compression, encryption, or encoding fails
    ///
    /// # Security
    /// - The body is compressed before encryption to reduce size and obscure patterns.
    /// - Encryption uses the configured algorithm and keys from the protocol instance.
    /// - The entire message (including header) is signed for authenticity.
    ///
    /// # Examples
    /// ```
    /// # use your_crate::CerberusProtocol;
    /// # use serde_json::json;
    /// # fn example(protocol: &CerberusProtocol) -> Result<(), Box<dyn std::error::Error>> {
    /// let header = json!({"type": "secure_message", "timestamp": 12345});
    /// let body = b"sensitive data";
    /// let encrypted = protocol.secure_encode(&header, body)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn secure_encode(&self, header: &serde_json::Value, body: &[u8]) -> Result<Vec<u8>> {
        let payload = compress(body)?;
        let payload = encrypt(&self.config, &payload)?;
        Ok(self.encode_message(header, &payload)?)
    }

    // Decodes an encrypted and compressed message.
    ///
    /// This method reverses the secure encoding process by first decoding the message,
    /// verifying its signature, then decrypting and decompressing the payload.
    ///
    /// # Arguments
    /// - `msg`: Byte slice containing the complete encrypted and compressed message
    ///
    /// # Returns
    /// - `Ok(BasicMessage)` with the decrypted and decompressed components: `header`, `body`, and `sign`
    /// - `Err(CerberusError)` if decoding, decryption, or decompression fails
    ///
    /// # Errors
    /// Returns an error if:
    /// - The message signature verification fails
    /// - The message cannot be decrypted (wrong key or corrupted data)
    /// - The decompression fails (corrupted or invalid compressed data)
    /// - The message format is invalid
    ///
    /// # Security
    /// - Verifies the message signature before decryption to ensure authenticity.
    /// - Decrypts using the configured algorithm and keys from the protocol instance.
    /// - Decompresses the payload to recover the original data.
    ///
    /// # Examples
    /// ```
    /// # use your_crate::CerberusProtocol;
    /// # fn example(protocol: &CerberusProtocol, encrypted_msg: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let decoded = protocol.secure_decode(encrypted_msg)?;
    /// println!("Decrypted header: {:?}", decoded.header);
    /// println!("Decrypted body length: {}", decoded.body.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn secure_decode(&self, msg: &[u8]) -> Result<BasicMessage> {
        let pre_slice = self.decode_message(msg)?;
        let decrypted = decrypt(&self.config, &pre_slice.body)?;
        let unzip = decompress(&decrypted)?;
        Ok(BasicMessage {
            header: pre_slice.header,
            body: unzip,
            sign: pre_slice.sign,
        })
    }
}
