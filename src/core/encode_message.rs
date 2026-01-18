use std::io::Write;

use openssl::{conf, pkey::{PKey, Private, Public}};
use serde::Serialize;

use crate::crypto::EncryptationConfig;


#[derive(Clone, Debug)]
pub enum CerberusType {
    SimpleAuthToken,
    DataAuthToken,


}

#[derive(Clone, Debug)]
pub struct CerberusConfig{
    version: CerberusType,
    target: PKey<Public>,
    source: PKey<Private>,
    encrip_config: EncryptationConfig,
}

pub struct Encoder {
    config: CerberusConfig,
    header: Vec<String>,
    payload: String,
    prebuild: Vec<u8>
}

impl Encoder {
    pub fn new(config: &CerberusConfig) -> Self {
        Self { config: config.clone(), header: vec![] , payload: String::new(), prebuild: vec![]}
    }

    pub fn add_header<T: AsRef<str>, A: Serialize + Clone>(&mut self, key: T, value: A) {
        self.header.push(format!("{}|>{}", key.as_ref(), serde_json::to_string(&value).unwrap()));
    }

    pub fn set_payload<T: Serialize + Clone>(&mut self, data: T) {
        self.payload = serde_json::to_string(&data).unwrap();
    }

    fn build_headers(&mut self)  {
        match self.config.version {
            CerberusType::SimpleAuthToken => {
                let mut buffer: Vec<u8> = Vec::new();
                buffer.write(&[0,0,0,0]);
                buffer.write(b"s");
                let mut header_buff: Vec<u8> = Vec::new();
                self.header.iter().map(|h| {
                    header_buff.write(h.as_bytes())
                });
                buffer.write(&header_buff.len().to_le_bytes());
                buffer.write_all(&header_buff);
                self.prebuild.write_all(&buffer);
            },
            CerberusType::DataAuthToken => {
                let mut buffer: Vec<u8> = Vec::new();
                buffer.write(&[0,0,0,0]);
                buffer.write(b"s");
                let mut header_buff: Vec<u8> = Vec::new();
                self.header.iter().map(|h| {
                    header_buff.write(h.as_bytes())
                });
                buffer.write(&header_buff.len().to_le_bytes());
                buffer.write_all(&header_buff);
                self.prebuild.write_all(&buffer);
            }
        }
    }
}
