

use core_cerberus::{compression::decompress_from_base64, crypto::{decrypt_from_base64, decrypt_symmetric_key, load_private_key, load_public_key, verify_signature}, utils::create_token};
use openssl::pkey::{PKey, Private, Public};
use pyo3::{exceptions::{PyIOError, PyRuntimeError}, prelude::*, types::PyList};

#[pyclass]
pub struct Cerberus{
    pub public_key_path: String,
    pub private_key_path: String,
    pub rsa_path: String,
    pub private: PKey<Private>,
    pub public: PKey<Public>,
    pub symetric: Vec<u8>,
}

#[pymethods]
impl Cerberus {
    #[new]
    fn new(public_key_path: String, private_key_path: String, rsa_path: String) -> Self {
        let public_bin = match std::fs::read(&public_key_path){
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Public key not found: {}", e);
                return PyResult::Err(PyIOError::new_err("Not found Public key file")).unwrap()
            }
        };
        let p_key = match load_public_key(&public_bin) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!("Error on load public key: {}", e);
                return PyResult::Err(PyIOError::new_err("Error on load public key")).unwrap()
            }
        };
        let p_private = match load_private_key(&private_key_path) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!("Error on load private key: {}", e);
                return PyResult::Err(PyIOError::new_err("Error on load private key")).unwrap()
            }
        };

        let symetric = match  decrypt_symmetric_key(&rsa_path, &p_private) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!("Error while decrypting the rsa key: {}", e);
                return PyResult::Err(PyIOError::new_err("Error while decrypting the rsa key")).unwrap()
            }
        };
        Self { public_key_path: public_key_path, 
            private_key_path: private_key_path, 
            rsa_path: rsa_path, public: p_key, 
            private: p_private, symetric: symetric }
    }
    fn create_token(&mut self,header: String, payload: String ) -> PyResult<String> {
        let token = match create_token(&header, &payload, &self.private_key_path, &self.rsa_path) {
            Ok(token) => token,
            Err(error) => {
                tracing::error!("Cerberus: {}", error);
                return PyResult::Err(PyRuntimeError::new_err(format!("Error wile generating token: {}", error)));
            }
        };
        PyResult::Ok(token)
    }
    fn verify(&mut self, token: String) -> PyResult<bool> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            tracing::error!("Malformed token, needed format 'zip.sign'");
                return PyResult::Err(PyRuntimeError::new_err("Wrong format"));
        }
        let compressed_base64 = parts[0];
        let signature_base64 = parts[1];
        let verf_result = match verify_signature(&self.public, compressed_base64.as_bytes(), signature_base64) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::error!("Verification error: {}", e);
                false
            }
        };
        PyResult::Ok(verf_result)
    }

    fn extract<'py>(&mut self, py: Python<'py>, token: String) -> Result<pyo3::Bound<'py, PyList>, PyErr> {
        let parts: Vec<&str> = token.split(".").collect();
        if parts.len() != 2 {
            tracing::error!("Malformed token");
            return PyResult::Err(PyRuntimeError::new_err(format!("Malformed token")));
        }
        let c_base64 = parts[0];
        let decompressed = match decompress_from_base64(c_base64) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Error descompressing the data");
                return PyResult::Err(PyRuntimeError::new_err(format!("Error descompressing the data: {}", e)));
            }
        };
        let inner_pars: Vec<&str> = decompressed.split(".").collect();
         if inner_pars.len() != 2 {
            tracing::error!("Malformed token");
            return PyResult::Err(PyRuntimeError::new_err(format!("Malformed token")));
        }
        let encrypted_header = inner_pars[0];
        let encrypted_payload = inner_pars[1];
        let header = match decrypt_from_base64(&encrypted_header, &self.symetric) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Error decrypting the header: {}", e);
                return PyResult::Err(PyRuntimeError::new_err(format!("Error decrypting the header: {}", e)));
            }
        };
        let payload = match decrypt_from_base64(&encrypted_payload, &self.symetric) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Error decrypting the payload: {}", e);
                return PyResult::Err(PyRuntimeError::new_err(format!("Error decrypting the payload: {}", e)));
            }
        };
        let out = PyList::new(py, &[header, payload]);
        Ok(out.unwrap())
    }
}

#[pymodule]
pub fn pycerberus(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Cerberus>()
}