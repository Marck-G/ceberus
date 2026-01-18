use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde_json::json;
use tracing::{info, Level};
use tracing_subscriber;

use cerberus::{
    core::{CerberusProtocol, HandshakeSession, SymmetricAlgo}, errors::error::CerberusError}
;

fn main() -> Result<(), CerberusError> {
    // Inicializar tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("Generando pares de claves RSA para cliente y servidor...");

    // Generar pares de claves
    let client_rsa = Rsa::generate(2048).unwrap();
    let server_rsa = Rsa::generate(2048).unwrap();

    let client_private = PKey::from_rsa(client_rsa).unwrap();
    let client_public = PKey::public_key_from_pem(&client_private.public_key_to_pem().unwrap()).unwrap();

    let server_private = PKey::from_rsa(server_rsa).unwrap();
    let server_public = PKey::public_key_from_pem(&server_private.public_key_to_pem().unwrap()).unwrap();

    info!("Claves generadas correctamente");

    // Crear handshake sessions
    let mut client_session = HandshakeSession::new(client_private.clone());
    let mut server_session = HandshakeSession::new(server_private.clone());

    // Cliente inicia handshake
    info!("Cliente inicia handshake...");
    let init_msg = client_session.initiate("client1", &client_public.public_key_to_pem().unwrap());

    // Servidor procesa Init y responde
    info!("Servidor procesa Init y responde...");
    let response_msg = server_session.process_init(
        &init_msg,
        "server1",
        &server_private,
        &server_public.public_key_to_pem().unwrap(),
    );

    // Cliente procesa Response y genera Complete
    info!("Cliente procesa Response y genera Complete...");
    let complete_msg = client_session.complete_handshake(&response_msg);

    // Servidor procesa Complete
    info!("Servidor procesa Complete...");
    server_session.process_complete(&complete_msg);

    info!("Handshake base completado");

    // Servidor genera y envía clave simétrica cifrada y firmada
    info!("Servidor genera clave simétrica y la envía al cliente...");
    let sym_msg = server_session.exchange_symmetric_key(cerberus::crypto::EncryptionType::Aes256Gcm, &server_private);

    // Cliente recibe, verifica y descifra clave simétrica
    info!("Cliente recibe y verifica clave simétrica...");
    let (key, algo) = client_session.receive_symmetric_key(&sym_msg, &server_public, &client_private);
    info!("Clave simétrica recibida y verificada, algoritmo: {:?}", algo);


    // Crear protocolos desde la sesión
    let client_protocol = CerberusProtocol::from_session(&client_session,  &client_private)?;
    let server_protocol = CerberusProtocol::from_session(&server_session,  &server_private)?;

    info!("Protocolos creados a partir de la sesión");

    // Enviar mensajes de prueba
    let header1 = json!({"type": "greeting", "timestamp": 1});
    let body1 = b"Hola desde cliente";

    info!("Cliente codifica y envía mensaje 1...");
    let encoded1 = client_protocol.encode_message(&header1, body1)?;

    info!("Servidor recibe y decodifica mensaje 1...");
    let decoded1 = server_protocol.decode_message(&encoded1)?;
    info!(
        "Servidor decodificó mensaje: header={}, body={}",
        String::from_utf8(decoded1.header.clone()).unwrap(),
        String::from_utf8(decoded1.body.clone()).unwrap()
    );

    // Segundo mensaje
    let header2 = json!({"type": "update", "timestamp": 2});
    let body2 = b"Actualizacion de estado";

    info!("Cliente codifica y envía mensaje 2...");
    let encoded2 = client_protocol.encode_message(&header2, body2)?;

    info!("Servidor recibe y decodifica mensaje 2...");
    let decoded2 = server_protocol.decode_message(&encoded2)?;
    info!(
        "Servidor decodificó mensaje: header={:?}, body={:?}",
        String::from_utf8(decoded2.header.clone()).unwrap(),
        String::from_utf8(decoded2.body.clone()).unwrap()
    );
    info!("Secure message");
    let header3 = json!({"type": "update", "t": 3});
    let body3 = b"Test seguro";
    info!("El cliente codifica seguro");
    let encode3 = client_protocol.secure_encode(&header3, body3)?;
    info!("El servidor decodifica");
    let decoded3 = server_protocol.secure_decode(&encode3).unwrap();
    info!(
        "Servidor decodificó mensaje: header={:?}, body={:?}",
        String::from_utf8(decoded3.header.clone()).unwrap(),
        String::from_utf8(decoded3.body.clone()).unwrap()
    );
    info!("Simulación de comunicación segura completada ✅");

    Ok(())
}
