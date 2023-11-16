mod context;

use neon::prelude::*;
use serde_json::{json, Value};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum MyError {
    MissingField(String),
    InvalidPayload,
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MyError::MissingField(field) => write!(f, "Missing field: {}", field),
            MyError::InvalidPayload => write!(f, "Invalid payload"),
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

fn get_field_array(
    cx: &mut FunctionContext,
    payload: Value,
    field: &str,
) -> NeonResult<Vec<String>> {
    match payload[field].as_array() {
        Some(arr) => Ok(arr
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect()),
        None => cx.throw_error(format!("Missing field: {}", field)),
    }
}

fn get_field_array_json(
    cx: &mut FunctionContext,
    payload: Value,
    field: &str,
) -> NeonResult<Vec<Value>> {
    match payload[field].as_array() {
        Some(arr) => Ok(arr.clone()),
        None => cx.throw_error(format!("Missing field: {}", field)),
    }
}

fn authorize(mut cx: FunctionContext) -> JsResult<JsString> {
    let payload: Handle<JsValue> = cx.argument(0)?;
    let payload_string = payload
        .downcast_or_throw::<JsString, _>(&mut cx)?
        .value(&mut cx);
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

    let result = json!(answer);
    let result_string = result.to_string();
    Ok(cx.string(result_string))
}

fn policy_from_json(mut cx: FunctionContext) -> JsResult<JsString> {
    let payload: Handle<JsValue> = cx.argument(0)?;
    let payload_string = payload
        .downcast_or_throw::<JsString, _>(&mut cx)?
        .value(&mut cx);

    let payload: Value = match serde_json::from_str(&payload_string) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("Failed to parse JSON"),
    };

    let policies = get_field_array_json(&mut cx, payload.clone(), "policies")?;

    let answer = match context::from_json(policies) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("JSON conversion failed"),
    };

    Ok(cx.string(answer))
}

fn policy_to_json(mut cx: FunctionContext) -> JsResult<JsString> {
    let payload: Handle<JsValue> = cx.argument(0)?;
    let payload_string = payload
        .downcast_or_throw::<JsString, _>(&mut cx)?
        .value(&mut cx);

    let answer = match context::to_json(&payload_string) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("JSON conversion failed"),
    };

    let result = json!(answer);
    let result_string = result.to_string();
    Ok(cx.string(result_string))
}

fn validate_policy(mut cx: FunctionContext) -> JsResult<JsString> {
    let payload: Handle<JsValue> = cx.argument(0)?;
    let payload_string = payload
        .downcast_or_throw::<JsString, _>(&mut cx)?
        .value(&mut cx);
    let payload: Value = match serde_json::from_str(&payload_string) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("Failed to parse JSON"),
    };

    let policy = get_field(&mut cx, payload.clone(), "policy")?;
    let additional_schema_fragments =
        get_field_array(&mut cx, payload.clone(), "additional_schema_fragments")?;

    let additional_schema_fragments_str: Vec<&str> = additional_schema_fragments
        .iter()
        .map(AsRef::as_ref)
        .collect();

    if policy.to_string().trim().is_empty() {
        return cx.throw_error("Invalid payload");
    }

    let answer = match context::validate_policy(&policy, Some(additional_schema_fragments_str)) {
        Ok(v) => v,
        Err(_) => return cx.throw_error("Validation failed"),
    };

    let result = json!(answer);
    let result_string = result.to_string();
    Ok(cx.string(result_string))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hello", hello)?;
    cx.export_function("authorize", authorize)?;
    cx.export_function("policy_to_json", policy_to_json)?;
    cx.export_function("policy_from_json", policy_from_json)?;
    cx.export_function("validate_policy", validate_policy)?;
    Ok(())
}
