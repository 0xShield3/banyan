use crate::MyError;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, Policy, PolicyId, PolicySet, Request,
    Response, Schema, SchemaFragment, ValidationMode, ValidationResult, Validator,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;

use serde::Serialize;

#[derive(Serialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

#[derive(Serialize)]
pub struct IPolicyStatementResult {
    policy_id: String,
    invoked: bool,
    annotations: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct IPolicyEnginePolicyResponse {
    reasons: Vec<IPolicyStatementResult>,
    decision: PolicyDecision,
    errors: Vec<String>,
}

pub fn validate_policy(
    policy: &str,
    additional_schema_fragments: Option<Vec<&str>>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let schema_file = include_str!("../resource/policySchema.json");
    let schema_a: SchemaFragment = SchemaFragment::from_str(schema_file)?;
    let mut schema_fragments = vec![schema_a];

    if let Some(fragments) = additional_schema_fragments {
        for fragment in fragments {
            let schema_fragment: SchemaFragment = SchemaFragment::from_str(fragment)?;
            schema_fragments.push(schema_fragment);
        }
    }

    let schema = Schema::from_schema_fragments(schema_fragments)?;
    let validator = Validator::new(schema);

    let p = PolicySet::from_str(&policy)?;
    let result = Validator::validate(&validator, &p, ValidationMode::default());
    if ValidationResult::validation_passed(&result) {
        return Ok(json!({ "valid": true }));
    } else {
        let e = ValidationResult::validation_errors(&result);
        let a = e.map(|e| e.to_string()).collect::<Vec<_>>().join("\n ");
        println!("Validation errors: {:?}", a);
        return Err(a.into());
    }
}

pub fn is_authorized(
    principal: &str,
    action: &str,
    resource: &str,
    policy: &str,
    entities: &str,
    context: &Value,
) -> Result<IPolicyEnginePolicyResponse, MyError> {
    let p: EntityUid = principal
        .to_string()
        .parse()
        .map_err(|_| MyError::InvalidPayload)?;
    let a = action
        .to_string()
        .parse()
        .map_err(|_| MyError::InvalidPayload)?;
    let r = resource
        .to_string()
        .parse()
        .map_err(|_| MyError::InvalidPayload)?;

    let ent = Entities::from_json_str(entities, None).map_err(|_| MyError::InvalidPayload)?;
    let cont =
        Context::from_json_value(context.clone(), None).map_err(|_| MyError::InvalidPayload)?;
    let policy_set = PolicySet::from_str(policy).map_err(|_| MyError::InvalidPayload)?;

    let request = Request::new(Some(p), Some(a), Some(r), cont);
    let ans = execute_query(&request, &policy_set, ent);
    print_answer(&ans, &policy_set);
    format_answer(&ans, &policy_set)
}

fn execute_query(request: &Request, policies: &PolicySet, entities: Entities) -> Response {
    let authorizer = Authorizer::new();
    authorizer.is_authorized(request, &policies, &entities)
}

fn print_answer(response: &Response, policies: &PolicySet) {
    match response.decision() {
        Decision::Allow => println!("ALLOW -> {:?}", response),
        Decision::Deny => println!("DENY -> {:?}", response),
    }
    for reason in response.diagnostics().reason() {
        //print all the annotations
        for (key, value) in policies.policy(&reason).unwrap().annotations() {
            println!("PolicyID: {}\tKey:{} \tValue:{}", reason, key, value);
        }
    }
    println!("------------------\n");
}

pub fn format_answer(
    response: &Response,
    policies: &PolicySet,
) -> Result<IPolicyEnginePolicyResponse, MyError> {
    let mut reasons = Vec::new();
    let mut errors = Vec::new();

    for policy in policies.policies() {
        let mut attrs = HashMap::new();
        for (key, value) in policy.annotations() {
            attrs.insert(key.to_string(), value.to_string());
        }

        let invoked = response
            .diagnostics()
            .reason()
            .any(|reason| *reason == *policy.id());

        reasons.push(IPolicyStatementResult {
            policy_id: policy.id().to_string(),
            invoked,
            annotations: attrs,
        });
    }

    let decision = match response.decision() {
        Decision::Allow => PolicyDecision::Allow,
        Decision::Deny => PolicyDecision::Deny,
    };

    // Add errors from diagnostics to the errors vector
    for error in response.diagnostics().errors() {
        errors.push(error.to_string());
    }

    Ok(IPolicyEnginePolicyResponse {
        reasons,
        decision,
        errors,
    })
}

pub fn to_json(policy: &str) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let policy_set = PolicySet::from_str(policy).map_err(|_| MyError::InvalidPayload)?;
    let mut policy_set_json = Vec::<Value>::new();

    for policy in policy_set.policies() {
        let policy_json: Result<Value, Box<dyn std::error::Error>> =
            Policy::to_json(&policy).map_err(|e| e.into());

        policy_set_json.push(policy_json?);
    }
    println!("result: {:?}", policy_set_json);
    Ok(policy_set_json)
}
// pub fn from_json(policies: Vec<Value>) -> Result<String, Box<dyn std::error::Error>> {
//     let mut policy_set = PolicySet::new();

//     for (id, policy_json) in policies.into_iter().enumerate() {
//         let policy_id_str = format!("policy{}", id);
//         let policy_id = PolicyId::from_str(&policy_id_str)?;
//         let policy = Policy::from_json(Some(policy_id), policy_json)?;
//         // let policy = Policy::from_json(None, policy_json)?;
//         policy_set.add(policy)?;
//     }

//     Ok(policy_set.to_string())
// }

pub fn from_json(policies: Vec<Value>) -> Result<String, Box<dyn std::error::Error>> {
    let mut policy_strings = Vec::new();

    for (id, policy_json) in policies.into_iter().enumerate() {
        let policy_id_str = format!("policy{}", id);
        let policy_id = PolicyId::from_str(&policy_id_str)?;
        let policy = Policy::from_json(Some(policy_id), policy_json)?;
        policy_strings.push(policy.to_string());
    }

    Ok(policy_strings.join("\n"))
}