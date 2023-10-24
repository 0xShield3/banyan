mod context;

use neon::prelude::*;
use serde_json::{json, Value};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum MyError {
    MissingField(String),
    InvalidPayload,
    // Add other kinds of errors here
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MyError::MissingField(field) => write!(f, "Missing field: {}", field),
            MyError::InvalidPayload => write!(f, "Invalid payload"),
            // Handle other kinds of errors here
        }
    }
}

impl Error for MyError {}

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("hello node"))
}


fn get_field(cx: &mut FunctionContext, payload: Value, field: &str) -> NeonResult<String> {
    match payload[field].as_str() {
        Some(s) => Ok(s.to_string()),
        None => cx.throw_error(format!("Missing field: {}", field)),
    }
}

fn authorize(mut cx: FunctionContext) -> JsResult<JsString> {
    let payload: Handle<JsValue> = cx.argument(0)?;
    let payload_string = payload.downcast_or_throw::<JsString, _>(&mut cx)?.value(&mut cx);
    let payload: Value = match serde_json::from_str(&payload_string) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("Failed to parse JSON"),
    };

    let principal = get_field(&mut cx, payload.clone(), "principal")?;
    let action = get_field(&mut cx, payload.clone(), "action")?;
    let resource = get_field(&mut cx, payload.clone(), "resource")?;
    let policy = get_field(&mut cx, payload.clone(), "policy")?;
    let entities = get_field(&mut cx, payload.clone(), "entities")?;
    let context = get_field(&mut cx, payload.clone(), "context")?;
    let context_value: Value = match serde_json::from_str(&context) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("Failed to parse context JSON"),
    };


    if payload.to_string().trim().is_empty()
        || principal.trim().is_empty()
        || action.trim().is_empty()
        || resource.trim().is_empty()
        || policy.trim().is_empty()
        || entities.trim().is_empty()
    {
        return cx.throw_error("Invalid payload");
    }
    
    let answer = match context::is_authorized(
        &principal,
        &action,
        &resource,
        &policy,
        &entities,
        &context_value,
    ) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("Authorization failed"),
    };

    let result = json!({ "result": answer });
    let result_string = result.to_string();
    Ok(cx.string(result_string))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hello", hello)?;
    cx.export_function("authorize", authorize)?;
    Ok(())
}
