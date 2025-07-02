// Use #[neon::export] to export Rust functions as JavaScript functions.
// See more at: https://docs.rs/neon/latest/neon/attr.export.html

use std::fs::read;

use core_cerberus::crypto::{decrypt_symmetric_key, load_private_key, load_public_key};
use neon::{
    prelude::{Context, FunctionContext, ModuleContext},
    result::JsResult,
    types::{JsBox, JsError, JsString, JsValue},
};
use neon_serde::from_value;
use serde_json::Value;

use crate::init_f::Cerberus;

mod init_f;

fn js_constructor(mut ctx: FunctionContext<'_>) -> JsResult<JsBox<Cerberus>> {
    let private_key_path: String = ctx.argument::<JsString>(0)?.value(&mut ctx) as String;
    let public_key_path: String = ctx.argument::<JsString>(1)?.value(&mut ctx) as String;
    let rsa_key: String = ctx.argument::<JsString>(2)?.value(&mut ctx) as String;
    let public_bin = match read(&public_key_path) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Error while loading public key file: {}", e);
            return ctx.throw_error(format!("Error loading public key: {}", e));
        }
    };
    let p_key = match load_public_key(&public_bin) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Error while loading public key file: {}", e);
            return ctx.throw_error(format!("Error loading public key: {}", e));
        }
    };
    let p_priv = match load_private_key(&private_key_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Error while loading private key file: {}", e);
            return ctx.throw_error(format!("Error loading private key: {}", e));
        }
    };
    let symm = match decrypt_symmetric_key(&rsa_key, &p_priv) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Error while loading key file: {}", e);
            return ctx.throw_error(format!("Error loading key: {}", e));
        }
    };
    let out = Cerberus::new(
        public_key_path,
        p_key,
        p_priv,
        symm,
        private_key_path,
        rsa_key,
    );
    Ok(ctx.boxed(out))
}

fn js_create(mut ctx: FunctionContext) -> JsResult<JsString> {
    let j_header = ctx.argument::<JsValue>(0).unwrap();
    let j_payloads = ctx.argument::<JsValue>(1).unwrap();
    let v_header: Value = from_value(&mut ctx, j_header).unwrap();
    let v_payload: Value = from_value(&mut ctx, j_payloads).unwrap();
    let header = serde_json::to_string(&v_header)?;
    let payload = serde_json::to_string(&v_payload).unwrap();
    let this = ctx
        .this()
        .unwrap()
        .downcast::<JsBox<Cerberus>>(&mut ctx)
        .unwrap();
    let token = match this.create(header, payload) {
        Ok(token) => token,
        Err(e) => {
            return ctx.throw_error(e);
        }
    };
    Ok(token)
}

#[neon::main]
fn main(mut ctx: ModuleContext) -> NeonResult<()> {
    ctx.export_function("cerberusNew", Cerberus::new);
    ctx.export_function("cerberusCreate", Cerberus::create);
    ctx.export_function("cerberusVerify", Cerberus::verify);
    ctx.export_function("cerberusExtract", Cerberus::extract);
    Ok(())
}
