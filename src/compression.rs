use base64::{engine::general_purpose, Engine as _};
use zstd::{decode_all, stream::encode_all};
use std::io::Cursor;

/// Comprime los datos con ZSTD y devuelve el resultado en Base64URL sin padding
pub fn compress_to_base64(data: &str) -> Result<String, String> {
    let compressed = encode_all(Cursor::new(data), 0)
        .map_err(|e| format!("Error comprimiendo: {}", e))?;

    let base64 = general_purpose::URL_SAFE_NO_PAD.encode(compressed);

    Ok(base64)
}

/// Descomprime una cadena base64url zstd comprimida y devuelve el String original
pub fn decompress_from_base64(base64_data: &str) -> Result<String, String> {
    // Decodificar desde Base64URL sin padding
    let compressed_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(base64_data)
        .map_err(|e| format!("Error decodificando Base64: {}", e))?;

    // Descomprimir usando zstd
    let decompressed_bytes = decode_all(Cursor::new(compressed_bytes))
        .map_err(|e| format!("Error descomprimiendo: {}", e))?;

    // Convertir a String
    let result = String::from_utf8(decompressed_bytes)
        .map_err(|e| format!("Error decodificando UTF-8: {}", e))?;

    Ok(result)
}