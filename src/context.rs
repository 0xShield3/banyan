use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, Policy, PolicySet, Request, Response,
    Schema, SchemaFragment, ValidationMode, ValidationResult, Validator,
};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use crate::MyError;

pub fn validate_policy(
    policy: &str,
    additional_schema_fragments: Option<Vec<&str>>,
) -> Result<(), Box<dyn std::error::Error>> {
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
        return Ok(());
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
) -> Result<HashMap<String, HashMap<String, String>>, MyError> {
    let p: EntityUid = principal.to_string().parse().map_err(|_| MyError::InvalidPayload)?;
    let a = action.to_string().parse().map_err(|_| MyError::InvalidPayload)?;
    let r = resource.to_string().parse().map_err(|_| MyError::InvalidPayload)?;

    let ent = Entities::from_json_str(entities, None).map_err(|_| MyError::InvalidPayload)?;
    let cont = Context::from_json_value(context.clone(), None).map_err(|_| MyError::InvalidPayload)?;
    let policy_set = PolicySet::from_str(policy).map_err(|_| MyError::InvalidPayload)?;

    let request = Request::new(Some(p), Some(a), Some(r), cont);
    let ans = execute_query(&request, &policy_set, ent);
    print_answer(&ans, &policy_set);
    Ok(format_answer(&ans, &policy_set))
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

fn format_answer(
    response: &Response,
    policies: &PolicySet,
) -> HashMap<String, HashMap<String, String>> {
    let mut result = HashMap::new();
    for policy in policies.policies() {
        let mut attrs = HashMap::new();
        for (key, value) in policy.annotations() {
            attrs.insert(key.to_string(), value.to_string());
        }
        if response
            .diagnostics()
            .reason()
            .any(|reason| *reason == *policy.id())
        {
            attrs.insert("reason".to_string(), true.to_string());
        } else {
            attrs.insert("reason".to_string(), false.to_string());
        }

        match response.decision() {
            Decision::Allow => {
                attrs.insert("decision".to_string(), "allow".to_string());
            }
            Decision::Deny => {
                attrs.insert("decision".to_string(), "deny".to_string());
            }
        }
        result.insert(policy.id().to_string(), attrs);
    }
    result
}

pub fn to_json(policy: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let p = Policy::from_str(&policy)?;
    let result = Policy::to_json(&p).map_err(|e| e.into());
    println!("result: {:?}", result);
    result
}
