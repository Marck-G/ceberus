# Cerberus Protocol

<center>

![](assets/logo.png)


</center>


A high-security communication protocol implementing hybrid cryptography for secure client-server communications. Cerberus combines RSA asymmetric encryption for key exchange and authentication with fast symmetric encryption (AES-256-GCM or ChaCha20-Poly1305) for message payload encryption.
# Overview

Cerberus Protocol is designed for applications requiring end-to-end encrypted communications with strong authentication guarantees. It provides:

- **Mutual Authentication**: Both parties verify each other's identity during handshake
- **Forward Secrecy**: Unique session keys for each connection
- **Integrity Protection**: All messages are digitally signed and authenticated
- **Flexible Encryption**: Support for both AES-256-GCM and ChaCha20-Poly1305
- **Replay Attack Prevention**: Nonce-based protection mechanism

# Features

- [x] RSA-based asymmetric key exchange
- [x] SHA3-256 digital signatures
- [x] Authenticated Encryption with Associated Data (AEAD)
- [x] Compression support for efficient bandwidth usage
- [x] Structured message format with JSON headers
- [ ] Token-based authentication variants
- [ ] WASM compatibility (planned migration to RustCrypto)

# Protocol Flow
## 1. Handshake Phase
The handshake establishes a secure channel through a three-way exchange:
```
Client                                    Server
  |                                         |
  |  (1) Init                               |
  |  - agent_id                             |
  |  - nonce_client                         |
  |  - public_cert_client                   |
  |---------------------------------------->|
  |                                         |
  |                        (2) Response     |
  |                        - server_id      |
  |                        - nonce_server   |
  |                        - sign(nonce_c)  |
  |                        - public_cert_s  |
  |<----------------------------------------|
  |                                         |
  |  (3) Complete                           |
  |  - iv (session IV)                      |
  |  - sign(nonce_server)                   |
  |---------------------------------------->|
  |                                         |
  |  (4) SymmetricKey (optional)            |
  |                        - algo           |
  |                        - encrypted_key  |
  |                        - signature      |
  |<----------------------------------------|
  |                                         |
```
### Step 1: Init (Client → Server)

- Client generates a random 12-byte nonce
- Client sends its agent ID, nonce, and public certificate (PEM format)

### Step 2: Response (Server → Client)

- Server verifies client's public key
- Server signs the client's nonce with its private key (proves server has the private key)
- Server generates its own nonce
- Server sends: server ID, server nonce, signature of client nonce, and server's public certificate

### Step 3: Complete (Client → Server)

- Client verifies server's signature on its nonce
- Client generates a random 12-byte IV for the session
- Client signs the server's nonce
- Client sends: session IV and signature of server nonce

### Step 4: Symmetric Key Exchange (Server → Client) - Optional

- Server generates a random 32-byte symmetric key
- Server encrypts the key using client's RSA public key (OAEP padding)
- Server signs the encrypted message (algo byte + encrypted key)
- Server sends: algorithm identifier, encrypted symmetric key, and signature

**After handshake completion, both parties have**:

- Each other's verified public keys
- A shared session IV
- (Optional) A shared symmetric encryption key
- Protection against man-in-the-middle attacks through mutual signature verification

## 2. Secure Communication Phase
Once the handshake is complete, parties can exchange encrypted messages:
```rust
rustuse cerberus::{CerberusProtocol, EncryptationConfig, EncryptionType};
use serde_json::json;

// Create protocol from completed handshake session
let protocol = CerberusProtocol::from_session(&session, &private_key)?;

// Send a secure message
let header = json!({
    "type": "data",
    "timestamp": 1234567890
});
let payload = b"Sensitive information";

// Compress, encrypt, sign
let encrypted_msg = protocol.secure_encode(&header, payload)?;

// On receiving end: verify, decrypt, decompress
let decoded = protocol.secure_decode(&encrypted_msg)?;
```
# Message Format
## Basic Message Structure
All Cerberus messages follow this binary format:
```
[HEADER_LENGTH: 4 bytes] [HEADER_JSON] [BODY] [SIGNATURE]
```
- `Header Length`: 4-byte little-endian integer specifying JSON header size
- `Header JSON`: UTF-8 encoded JSON metadata
- `Body`: Binary payload (optionally compressed and encrypted)
- `Signature`: Digital signature (SHA3-256) covering header + body

## Secure Message Flow
```
Original Data
    ↓
Compress (body only)
    ↓
Encrypt (compressed body)
    ↓
Encode (header + encrypted body)
    ↓
Sign (entire message)
    ↓
Transmit
```
### Cryptographic Primitives
#### Asymmetric Encryption

- **Algorithm**: RSA with OAEP padding
- **Key Size**: 2048-bit minimum (recommended: 4096-bit)
- **Usage**: Key exchange, digital signatures

#### Symmetric Encryption
##### AES-256-GCM

- **Key Size**: 256 bits (32 bytes)
- **Nonce/IV**: 96 bits (12 bytes)
- **Best for**: Platforms with AES-NI hardware acceleration
- **Properties**: NIST-approved, widely supported

##### ChaCha20-Poly1305

- **Key Size:** 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes)
- **Best for**: Platforms without hardware acceleration
- **Properties**: Constant-time, resistant to timing attacks (RFC 8439)

# Digital Signatures

- **Algorithm**: SHA3-256
- **Usage**: Message authentication, handshake verification

# Compression

Used before encryption to reduce payload size and obscure patterns

# Security Considerations
## Nonce Management

- **Critical**: Never reuse the same IV/nonce with the same key
- Each handshake generates unique nonces for replay protection
- Session IV must be unique per connection

## Key Security

- Private keys must never be transmitted
- Store private keys securely (encrypted at rest)
- Use secure random number generators for all cryptographic material

## Signature Verification

- Always verify signatures before processing messages
- Verify peer's public key during handshake to prevent MITM attacks
- Signatures cover both header and body for complete integrity

## Session Management

- Establish new sessions periodically
- Implement session timeout mechanisms
- Consider implementing perfect forward secrecy with ephemeral keys

# API Reference
## Core Types
```rust
// Protocol instance for secure communication
pub struct CerberusProtocol {
    target: PKey<Public>,      // Peer's public key
    source: PKey<Private>,     // Own private key
    config: EncryptationConfig // Encryption settings
}

// Encryption configuration
pub struct EncryptationConfig {
    pub algo: EncryptionType,  // AES-256-GCM or ChaCha20-Poly1305
    pub key: Vec<u8>,          // 32 bytes
    pub iv: Vec<u8>,           // 12 bytes
}

// Handshake session management
pub struct HandshakeSession {
    pub source: PKey<Private>,
    pub target: Option<PKey<Public>>,
    pub nonce_local: [u8; 12],
    pub nonce_remote: Option<[u8; 12]>,
    pub iv: Option<[u8; 12]>,
    pub symmetric_key: Option<Vec<u8>>,
    pub algo: EncryptionType,
}
```
## Key Methods
### Handshake
```rust
// Client side
let mut session = HandshakeSession::new(client_private_key);
let init_msg = session.initiate("client_001", &client_public_pem);
// ... send init_msg to server ...

// ... receive response from server ...
let complete_msg = session.complete_handshake(&response_data);
// ... send complete_msg to server ...

// Server side
let mut session = HandshakeSession::new(server_private_key);
// ... receive init from client ...
let response_msg = session.process_init(
    &init_data,
    "server_001",
    &server_private_key,
    &server_public_pem
);
// ... send response_msg to client ...

// ... receive complete from client ...
session.process_complete(&complete_data);

// Optional: Exchange symmetric key
let key_msg = session.exchange_symmetric_key(
    EncryptionType::Aes256Gcm,
    &server_private_key
);
// ... send to client ...

// Client receives symmetric key
let (key, algo) = session.receive_symmetric_key(
    &key_msg,
    &server_public_key,
    &client_private_key
);
```
### Message Exchange
```rust
// Create protocol from session
let protocol = CerberusProtocol::from_session(&session, &private_key)?;

// Basic (signed but not encrypted)
let encoded = protocol.encode_message(&header, &body)?;
let decoded = protocol.decode_message(&encoded)?;

// Secure (compressed, encrypted, signed)
let encrypted = protocol.secure_encode(&header, &body)?;
let decrypted = protocol.secure_decode(&encrypted)?;
```
## Error Handling
```rust
pub enum CerberusError {
    KeyReadError(String),      // Failed to read key
    KeyParseError(String),     // Failed to parse key
    KeyFormatError(String),    // Incorrect key format
    KeyBinaryError,            // Binary conversion error
    KeyLengthError(i64),       // Wrong key size (expected size provided)
    IVLengthError(i64),        // Wrong IV size (expected size provided)
    EncryptionError(String),   // Encryption failed
    DecryptionError(String),   // Decryption/auth failed
    CodificationError(String), // Message encoding/decoding failed
    SignError(String),         // Signature operation failed
    MessageLengthError(String) // Invalid message length
}
```
# Use Cases

- **Microservices Communication:** Secure inter-service messaging
- **IoT Device Management**: Authenticated device-to-server communication
- **Financial Systems**: High-security transaction processing
- **Healthcare Applications**: HIPAA-compliant data exchange
- **Remote Administration**: Secure command and control channels

# Roadmap
## Current Version

- [x] RSA-based handshake
- [x] Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
- [x] Digital signatures (SHA3-256)
- [x] Message compression
- [x] Flexible message format

## Planned Features

### Token-based authentication variants

- Simple token authentication
- Token with embedded data
- Compact signed data blocks for web applications


### WASM Support

- Migration from OpenSSL to RustCrypto
- Client-side cryptography in web browsers
- Additional security layer for web applications


### Additional Features

- Perfect Forward Secrecy (ephemeral key exchange)
- Certificate chain validation
- Key rotation mechanisms
- Session resumption



# Performance Considerations

- **AES-256-GCM**: ~3-5 GB/s on modern CPUs with AES-NI
- **ChaCha20-Poly1305**: ~1-2 GB/s (more consistent across platforms)
- **RSA Operations**: Used only during handshake (expensive but infrequent)
- **Compression**: Reduces bandwidth at the cost of CPU (beneficial for large payloads)

---
<center>
Per Aspera Ad Astra

![](assets/katalyst.png)
</center>
---



> Note: This is a custom protocol implementation. For production use, ensure thorough security audits and testing. Consider using established protocols like TLS 1.3 for general-purpose secure communications unless you have specific requirements that Cerberus addresses.