use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Padding,
    sign::{Signer, Verifier},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::EncryptionType;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum SymmetricAlgo {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandshakeMessage {
    Init {
        agent_id: String,
        nonce: [u8; 12],
        public_cert: Vec<u8>,
    },
    Response {
        server_id: String,
        nonce: [u8; 12],
        sign: Vec<u8>,
        public_cert: Vec<u8>,
    },
    Complete {
        iv: [u8; 12],
        sign: Vec<u8>,
    },
}

/// Representa un mensaje decodificado de CerberusProtocol.
///
/// Contiene:
/// - `header`: bytes JSON del header del mensaje
/// - `body`: payload binario
/// - `sign`: firma digital que asegura integridad y autenticidad
pub struct HandshakeSession {
    /// Clave privada del agente, usada para firmar mensajes durante handshake
    pub source: PKey<Private>,

    /// Clave pública del peer (se establece durante handshake)
    pub target: Option<PKey<Public>>,

    /// Nonce generado por este agente
    pub nonce_local: [u8; 12],

    /// Nonce recibido del peer (se establece durante handshake)
    pub nonce_remote: Option<[u8; 12]>,

    /// IV acordado para la sesión (se establece al final del handshake)
    pub iv: Option<[u8; 12]>,
    pub symmetric_key: Option<Vec<u8>>,
    pub algo: EncryptionType,
}

#[allow(dead_code)]
impl HandshakeSession {
    /// Crea una nueva sesión de handshake.
    ///
    /// Genera automáticamente un nonce local seguro para iniciar el handshake.
    ///
    /// # Parámetros
    /// - `source`: Clave privada del agente que ejecuta la sesión
    ///
    /// # Retorna
    /// - `HandshakeSession` listo para iniciar el intercambio con un peer
    ///
    /// # Seguridad
    /// - El nonce generado es aleatorio y único para esta sesión
    /// - La clave privada debe mantenerse segura y no ser compartida
    pub fn new(source: PKey<Private>) -> Self {
        let mut nonce_local = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_local);

        Self {
            source,
            target: None,
            nonce_local,
            nonce_remote: None,
            iv: None,
            symmetric_key: None,
            algo: EncryptionType::Aes256Gcm,
        }
    }

    /// Genera el mensaje de inicio del handshake (Init) que debe enviarse al peer.
    ///
    /// # Parámetros
    /// - `agent_id`: Identificador del agente que inicia el handshake
    /// - `public_cert`: Certificado público del agente (clave pública) para que el peer lo use
    ///
    /// # Retorna
    /// - `Vec<u8>`: mensaje Init serializado (JSON)
    ///
    /// # Seguridad
    /// - Incluye un nonce único que será firmado por el peer en su respuesta
    /// - Este mensaje no contiene información sensible, solo la clave pública y nonce
    pub fn initiate(&self, agent_id: &str, public_cert: &[u8]) -> Vec<u8> {
        let msg = HandshakeMessage::Init {
            agent_id: agent_id.to_string(),
            nonce: self.nonce_local,
            public_cert: public_cert.to_vec(),
        };
        serde_json::to_vec(&msg).unwrap()
    }

    /// Procesa un mensaje Init recibido (servidor) y genera la respuesta (Response).
    ///
    /// # Parámetros
    /// - `data`: Bytes recibidos que contienen el Init message
    /// - `server_id`: Identificador del servidor
    /// - `server_private`: Clave privada del servidor para firmar el nonce del cliente
    /// - `server_cert`: Certificado público del servidor
    ///
    /// # Retorna
    /// - `Vec<u8>`: mensaje Response serializado (JSON)
    ///
    /// # Seguridad
    /// - Firma el nonce recibido del cliente para autenticar el servidor
    /// - Genera un nonce propio del servidor para prevenir replay attacks
    /// - La clave pública del cliente se almacena en `target` para verificar firmas futuras
    pub fn process_init(
        &mut self,
        data: &[u8],
        server_id: &str,
        server_private: &PKey<Private>,
        server_cert: &[u8],
    ) -> Vec<u8> {
        let msg: HandshakeMessage = serde_json::from_slice(data).unwrap();

        if let HandshakeMessage::Init {
            agent_id: _,
            nonce,
            public_cert,
        } = msg
        {
            self.target = Some(PKey::public_key_from_pem(&public_cert).unwrap());
            self.nonce_remote = Some(nonce);

            // Firma del nonce del cliente
            let mut signer = openssl::sign::Signer::new(
                openssl::hash::MessageDigest::sha3_256(),
                server_private,
            )
            .unwrap();
            signer.update(&nonce).unwrap();
            let sign = signer.sign_to_vec().unwrap();

            // Generar nonce del servidor
            let mut nonce_server = [0u8; 12];
            rand::rng().fill_bytes(&mut nonce_server);
            self.nonce_local = nonce_server;

            let response = HandshakeMessage::Response {
                server_id: server_id.to_string(),
                nonce: nonce_server,
                sign,
                public_cert: server_cert.to_vec(),
            };

            serde_json::to_vec(&response).unwrap()
        } else {
            panic!("Expected Init message");
        }
    }

    /// Procesa el mensaje Response del peer (cliente) y genera el mensaje Complete.
    ///
    /// # Parámetros
    /// - `data`: Bytes recibidos que contienen el Response message del peer
    ///
    /// # Retorna
    /// - `Vec<u8>`: mensaje Complete serializado (JSON)
    ///
    /// # Seguridad
    /// - Verifica la firma del servidor usando su clave pública (`target`)
    /// - Genera un IV aleatorio para la sesión, que se almacenará en `self.iv`
    /// - Firma el nonce del servidor para garantizar autenticidad
    pub fn complete_handshake(&mut self, data: &[u8]) -> Vec<u8> {
        let msg: HandshakeMessage = serde_json::from_slice(data).unwrap();

        if let HandshakeMessage::Response {
            server_id: _,
            nonce,
            sign,
            public_cert,
        } = msg
        {
            self.target = Some(PKey::public_key_from_pem(&public_cert).unwrap());
            self.nonce_remote = Some(nonce);

            // Verificar firma del servidor
            let target_pub = self.target.as_ref().unwrap();
            let mut verifier =
                openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha3_256(), target_pub)
                    .unwrap();
            verifier.update(&self.nonce_local).unwrap();
            let result = verifier.verify(&sign).unwrap();
            assert!(result, "Server signature verification failed");

            // Generar IV para la sesión
            let mut iv = [0u8; 12];
            rand::rng().fill_bytes(&mut iv);
            self.iv = Some(iv);

            // Firmar nonce del servidor
            let mut signer =
                openssl::sign::Signer::new(openssl::hash::MessageDigest::sha3_256(), &self.source)
                    .unwrap();
            signer.update(&nonce).unwrap();
            let sign_nonce = signer.sign_to_vec().unwrap();

            let complete = HandshakeMessage::Complete {
                iv,
                sign: sign_nonce,
            };

            serde_json::to_vec(&complete).unwrap()
        } else {
            panic!("Expected Response message");
        }
    }

    /// Procesa el mensaje Complete recibido del peer (servidor) y almacena el IV final.
    ///
    /// # Parámetros
    /// - `data`: Bytes recibidos que contienen el Complete message del peer
    ///
    /// # Seguridad
    /// - Verifica la firma del cliente usando la clave pública del peer (`target`)
    /// - Almacena el IV acordado en `self.iv`
    /// - Después de esto, la sesión está lista para crear un `CerberusProtocol` completo
    pub fn process_complete(&mut self, data: &[u8]) {
        let msg: HandshakeMessage = serde_json::from_slice(data).unwrap();
        if let HandshakeMessage::Complete { iv, sign } = msg {
            // Verificar firma del cliente
            let target_pub = self.target.as_ref().unwrap();
            let mut verifier =
                openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha3_256(), target_pub)
                    .unwrap();
            verifier.update(&self.nonce_local).unwrap();
            let result = verifier.verify(&sign).unwrap();
            assert!(result, "Client signature verification failed");

            self.iv = Some(iv);
        } else {
            panic!("Expected Complete message");
        }
    }

    /// Genera una clave simétrica aleatoria y la cifra con la clave pública del peer.
    /// Devuelve el mensaje que se enviará al cliente.
    pub fn exchange_symmetric_key(
        &mut self,
        encrypt_algo: EncryptionType,
        server_private: &PKey<Private>,
    ) -> Vec<u8> {
        // 1️⃣ Generar clave simétrica
        let mut key_bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut key_bytes);
        let key_vec = key_bytes.to_vec();
        let algo = match encrypt_algo {
            EncryptionType::Aes256Gcm => SymmetricAlgo::Aes256Gcm,
            EncryptionType::ChaCha20Poly1305 => SymmetricAlgo::ChaCha20Poly1305,
        };
        // 2️⃣ Cifrar clave con clave pública del cliente
        let target_pub = self.target.as_ref().expect("Target public key not set");
        let rsa = target_pub.rsa().unwrap();
        let mut encrypted = vec![0u8; rsa.size() as usize];
        let len = rsa
            .public_encrypt(&key_vec, &mut encrypted, Padding::PKCS1_OAEP)
            .unwrap();
        encrypted.truncate(len);

        // 3️⃣ Preparar mensaje para firmar (algo byte + encrypted key)
        let mut msg_to_sign = Vec::with_capacity(1 + encrypted.len());
        msg_to_sign.push(algo.clone() as u8);
        msg_to_sign.extend_from_slice(&encrypted);

        // 4️⃣ Firmar
        let mut signer = Signer::new(MessageDigest::sha3_256(), server_private).unwrap();
        signer.update(&msg_to_sign).unwrap();
        let signature = signer.sign_to_vec().unwrap();

        // 5️⃣ Construir mensaje final [algo][encrypted_key][signature]
        let mut final_msg = msg_to_sign;
        final_msg.extend_from_slice(&signature);

        // 6️⃣ Guardar clave en sesión
        self.symmetric_key = Some(key_vec);
        self.algo = encrypt_algo;

        final_msg
    }

    /// Recibe la clave simétrica cifrada y la descifra usando la clave privada del cliente.
    pub fn receive_symmetric_key(
        &mut self,
        data: &[u8],
        server_pub: &PKey<Public>,
        client_private: &PKey<Private>,
    ) -> (Vec<u8>, SymmetricAlgo) {
        // 1️⃣ Leer el byte del algoritmo
        let algo = match data[0] {
            1 => SymmetricAlgo::Aes256Gcm,
            2 => SymmetricAlgo::ChaCha20Poly1305,
            _ => panic!("Unknown symmetric algorithm"),
        };

        let rsa = client_private.rsa().unwrap();
        let encrypted_len = rsa.size();
        if data.len() < (1 + encrypted_len) as usize {
            panic!("Received data too short");
        }

        let encrypted_key = &data[1..(1 + encrypted_len) as usize];
        let signature = &data[(1 + encrypted_len) as usize..];

        // 2️⃣ Verificar firma sobre [algo byte + encrypted_key]
        let mut verifier = Verifier::new(MessageDigest::sha3_256(), server_pub).unwrap();
        verifier
            .update(&data[..(1 + encrypted_len) as usize])
            .unwrap();
        if !verifier.verify(signature).unwrap() {
            panic!("Server signature verification failed");
        }

        // 3️⃣ Descifrar clave simétrica
        let mut key = vec![0u8; rsa.size() as usize];
        let len = rsa
            .private_decrypt(encrypted_key, &mut key, Padding::PKCS1_OAEP)
            .unwrap();
        key.truncate(len);

        self.symmetric_key = Some(key.clone());
        self.algo = match algo {
            SymmetricAlgo::Aes256Gcm => EncryptionType::Aes256Gcm,
            SymmetricAlgo::ChaCha20Poly1305 => EncryptionType::ChaCha20Poly1305,
        };
        (key, algo)
    }
}
