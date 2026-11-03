use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use aegis_native_engine::{ApprovedTarget, HttpMethod, RequestPurpose};
use serde_json::{json, Value};

use crate::{canonicalize_url, CanonicalUrl, CanonicalizationOutcome};

const HARD_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const HARD_MAX_VALUE_NODES: usize = 100_000;
const HARD_MAX_VALUE_DEPTH: usize = 64;
const HARD_MAX_TYPES: usize = 500;
const HARD_MAX_FIELDS_PER_TYPE: usize = 300;
const HARD_MAX_ARGUMENTS_PER_FIELD: usize = 64;
const HARD_MAX_OPERATIONS: usize = 500;
const HARD_MAX_TYPE_REF_DEPTH: usize = 16;
const MAX_GRAPHQL_NAME_BYTES: usize = 128;

pub const GRAPHQL_INTROSPECTION_QUERY: &str = "query AegisIntrospection { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: false) { name args { name defaultValue type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } } }";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphqlIntrospectionLimits {
    pub max_response_bytes: usize,
    pub max_value_nodes: usize,
    pub max_value_depth: usize,
    pub max_types: usize,
    pub max_fields_per_type: usize,
    pub max_arguments_per_field: usize,
    pub max_operations: usize,
}

impl Default for GraphqlIntrospectionLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: HARD_MAX_RESPONSE_BYTES,
            max_value_nodes: HARD_MAX_VALUE_NODES,
            max_value_depth: HARD_MAX_VALUE_DEPTH,
            max_types: HARD_MAX_TYPES,
            max_fields_per_type: HARD_MAX_FIELDS_PER_TYPE,
            max_arguments_per_field: HARD_MAX_ARGUMENTS_PER_FIELD,
            max_operations: HARD_MAX_OPERATIONS,
        }
    }
}

impl GraphqlIntrospectionLimits {
    fn validate(&self) -> Result<(), GraphqlSurfaceError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > HARD_MAX_RESPONSE_BYTES
            || self.max_value_nodes == 0
            || self.max_value_nodes > HARD_MAX_VALUE_NODES
            || self.max_value_depth == 0
            || self.max_value_depth > HARD_MAX_VALUE_DEPTH
            || self.max_types == 0
            || self.max_types > HARD_MAX_TYPES
            || self.max_fields_per_type == 0
            || self.max_fields_per_type > HARD_MAX_FIELDS_PER_TYPE
            || self.max_arguments_per_field == 0
            || self.max_arguments_per_field > HARD_MAX_ARGUMENTS_PER_FIELD
            || self.max_operations == 0
            || self.max_operations > HARD_MAX_OPERATIONS
        {
            return Err(GraphqlSurfaceError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphqlSurfaceError {
    InvalidLimits,
    InvalidTarget,
    InvalidEndpoint,
    IntrospectionNotAllowed,
    ResponseTooLarge,
    ParseFailed,
    ResponseContainsErrors,
    StructureLimitExceeded,
    TooManyTypes,
    TooManyFields,
    TooManyArguments,
    TooManyOperations,
    InvalidSchema,
}

impl Display for GraphqlSurfaceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "GraphQL introspection limits are invalid",
            Self::InvalidTarget => "approved target is invalid",
            Self::InvalidEndpoint => "GraphQL endpoint is outside the approved target",
            Self::IntrospectionNotAllowed => "GraphQL introspection was not explicitly allowed",
            Self::ResponseTooLarge => "GraphQL introspection response exceeded the size limit",
            Self::ParseFailed => "GraphQL introspection response could not be parsed",
            Self::ResponseContainsErrors => "GraphQL introspection returned errors",
            Self::StructureLimitExceeded => "GraphQL response exceeded depth or node limits",
            Self::TooManyTypes => "GraphQL type limit exceeded",
            Self::TooManyFields => "GraphQL field limit exceeded",
            Self::TooManyArguments => "GraphQL argument limit exceeded",
            Self::TooManyOperations => "GraphQL operation limit exceeded",
            Self::InvalidSchema => "GraphQL introspection schema is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for GraphqlSurfaceError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphqlIntrospectionPlan {
    pub endpoint: CanonicalUrl,
    pub method: HttpMethod,
    pub purpose: RequestPurpose,
    pub content_type: String,
    pub body: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GraphqlOperationKind {
    Query,
    Mutation,
    Subscription,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GraphqlArgument {
    pub name: String,
    pub type_signature: String,
    pub required: bool,
    pub has_default: bool,
    pub sensitive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphqlField {
    pub name: String,
    pub kind: GraphqlOperationKind,
    pub arguments: Vec<GraphqlArgument>,
    pub return_type: String,
    pub automatic_execution_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphqlSurface {
    pub endpoint: CanonicalUrl,
    pub fields: Vec<GraphqlField>,
}

/// Builds a fixed, read-only introspection request only after explicit customer approval.
pub fn plan_graphql_introspection(
    target: &ApprovedTarget,
    endpoint_url: &str,
    explicitly_allowed: bool,
) -> Result<GraphqlIntrospectionPlan, GraphqlSurfaceError> {
    target
        .validate()
        .map_err(|_| GraphqlSurfaceError::InvalidTarget)?;
    if !explicitly_allowed {
        return Err(GraphqlSurfaceError::IntrospectionNotAllowed);
    }
    let target_base = format!("{}{}", target.origin, target.path_prefix);
    let CanonicalizationOutcome::Accepted(endpoint) =
        canonicalize_url(target, &target_base, endpoint_url)
            .map_err(|_| GraphqlSurfaceError::InvalidEndpoint)?
    else {
        return Err(GraphqlSurfaceError::InvalidEndpoint);
    };
    let body = json!({
        "query": GRAPHQL_INTROSPECTION_QUERY,
        "operationName": "AegisIntrospection"
    })
    .to_string();
    Ok(GraphqlIntrospectionPlan {
        endpoint,
        method: HttpMethod::Post,
        purpose: RequestPurpose::Baseline,
        content_type: "application/json".to_string(),
        body,
    })
}

/// Reduces an approved introspection response to bounded root operation metadata.
pub fn import_graphql_introspection(
    endpoint: CanonicalUrl,
    response: &str,
    limits: GraphqlIntrospectionLimits,
) -> Result<GraphqlSurface, GraphqlSurfaceError> {
    limits.validate()?;
    if response.len() > limits.max_response_bytes {
        return Err(GraphqlSurfaceError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_str(response).map_err(|_| GraphqlSurfaceError::ParseFailed)?;
    validate_structure(&root, limits.max_value_nodes, limits.max_value_depth)?;
    if root
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err(GraphqlSurfaceError::ResponseContainsErrors);
    }
    let schema = root
        .pointer("/data/__schema")
        .and_then(Value::as_object)
        .ok_or(GraphqlSurfaceError::InvalidSchema)?;
    let types = schema
        .get("types")
        .and_then(Value::as_array)
        .ok_or(GraphqlSurfaceError::InvalidSchema)?;
    if types.len() > limits.max_types {
        return Err(GraphqlSurfaceError::TooManyTypes);
    }
    let mut types_by_name = BTreeMap::<String, &Value>::new();
    for graphql_type in types {
        let Some(name) = graphql_type.get("name").and_then(Value::as_str) else {
            continue;
        };
        let name = validated_graphql_name(name)?;
        if types_by_name.insert(name, graphql_type).is_some() {
            return Err(GraphqlSurfaceError::InvalidSchema);
        }
    }

    let roots = [
        ("queryType", GraphqlOperationKind::Query),
        ("mutationType", GraphqlOperationKind::Mutation),
        ("subscriptionType", GraphqlOperationKind::Subscription),
    ];
    let mut fields = Vec::new();
    let mut field_keys = BTreeSet::new();
    for (root_key, kind) in roots {
        let Some(root_name) = schema
            .get(root_key)
            .and_then(Value::as_object)
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let root_name = validated_graphql_name(root_name)?;
        let root_type = types_by_name
            .get(&root_name)
            .ok_or(GraphqlSurfaceError::InvalidSchema)?;
        let root_fields = root_type
            .get("fields")
            .and_then(Value::as_array)
            .ok_or(GraphqlSurfaceError::InvalidSchema)?;
        if root_fields.len() > limits.max_fields_per_type {
            return Err(GraphqlSurfaceError::TooManyFields);
        }
        for field in root_fields {
            if fields.len() >= limits.max_operations {
                return Err(GraphqlSurfaceError::TooManyOperations);
            }
            let imported = import_field(field, kind, &limits)?;
            if !field_keys.insert((kind, imported.name.clone())) {
                return Err(GraphqlSurfaceError::InvalidSchema);
            }
            fields.push(imported);
        }
    }
    fields.sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));
    Ok(GraphqlSurface { endpoint, fields })
}

fn import_field(
    value: &Value,
    kind: GraphqlOperationKind,
    limits: &GraphqlIntrospectionLimits,
) -> Result<GraphqlField, GraphqlSurfaceError> {
    let object = value
        .as_object()
        .ok_or(GraphqlSurfaceError::InvalidSchema)?;
    let name = validated_graphql_name(
        object
            .get("name")
            .and_then(Value::as_str)
            .ok_or(GraphqlSurfaceError::InvalidSchema)?,
    )?;
    let raw_arguments = object
        .get("args")
        .and_then(Value::as_array)
        .ok_or(GraphqlSurfaceError::InvalidSchema)?;
    if raw_arguments.len() > limits.max_arguments_per_field {
        return Err(GraphqlSurfaceError::TooManyArguments);
    }
    let mut argument_names = BTreeSet::new();
    let mut arguments = Vec::new();
    for argument in raw_arguments {
        let argument = argument
            .as_object()
            .ok_or(GraphqlSurfaceError::InvalidSchema)?;
        let argument_name = validated_graphql_name(
            argument
                .get("name")
                .and_then(Value::as_str)
                .ok_or(GraphqlSurfaceError::InvalidSchema)?,
        )?;
        if !argument_names.insert(argument_name.clone()) {
            return Err(GraphqlSurfaceError::InvalidSchema);
        }
        let type_signature = type_signature(
            argument
                .get("type")
                .ok_or(GraphqlSurfaceError::InvalidSchema)?,
            0,
        )?;
        let has_default = argument
            .get("defaultValue")
            .is_some_and(|value| !value.is_null());
        let required = type_signature.ends_with('!') && !has_default;
        arguments.push(GraphqlArgument {
            sensitive: is_sensitive_name(&argument_name),
            name: argument_name,
            type_signature,
            required,
            has_default,
        });
    }
    arguments.sort();
    let return_type = type_signature(
        object
            .get("type")
            .ok_or(GraphqlSurfaceError::InvalidSchema)?,
        0,
    )?;
    let automatic_execution_allowed =
        kind == GraphqlOperationKind::Query && !arguments.iter().any(|argument| argument.required);
    Ok(GraphqlField {
        name,
        kind,
        arguments,
        return_type,
        automatic_execution_allowed,
    })
}

fn type_signature(value: &Value, depth: usize) -> Result<String, GraphqlSurfaceError> {
    if depth >= HARD_MAX_TYPE_REF_DEPTH {
        return Err(GraphqlSurfaceError::InvalidSchema);
    }
    let object = value
        .as_object()
        .ok_or(GraphqlSurfaceError::InvalidSchema)?;
    match object.get("kind").and_then(Value::as_str) {
        Some("NON_NULL") => Ok(format!(
            "{}!",
            type_signature(
                object
                    .get("ofType")
                    .ok_or(GraphqlSurfaceError::InvalidSchema)?,
                depth + 1,
            )?
        )),
        Some("LIST") => Ok(format!(
            "[{}]",
            type_signature(
                object
                    .get("ofType")
                    .ok_or(GraphqlSurfaceError::InvalidSchema)?,
                depth + 1,
            )?
        )),
        Some("SCALAR" | "OBJECT" | "INTERFACE" | "UNION" | "ENUM" | "INPUT_OBJECT") => {
            validated_graphql_name(
                object
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(GraphqlSurfaceError::InvalidSchema)?,
            )
        }
        _ => Err(GraphqlSurfaceError::InvalidSchema),
    }
}

fn validate_structure(
    root: &Value,
    max_nodes: usize,
    max_depth: usize,
) -> Result<(), GraphqlSurfaceError> {
    let mut nodes = 0usize;
    let mut stack = vec![(root, 1usize)];
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > max_nodes || depth > max_depth {
            return Err(GraphqlSurfaceError::StructureLimitExceeded);
        }
        match value {
            Value::Array(values) => stack.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => stack.extend(values.values().map(|value| (value, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

fn validated_graphql_name(value: &str) -> Result<String, GraphqlSurfaceError> {
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > MAX_GRAPHQL_NAME_BYTES
        || !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(GraphqlSurfaceError::InvalidSchema);
    }
    Ok(value.to_string())
}

fn is_sensitive_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("apikey")
        || lower == "key"
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::{ApprovedTarget, HttpMethod, RequestPurpose};

    use super::{
        import_graphql_introspection, plan_graphql_introspection, GraphqlIntrospectionLimits,
        GraphqlOperationKind, GraphqlSurfaceError,
    };

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://api.example.com", "/api").unwrap()
    }

    #[test]
    fn plan_requires_explicit_approval_and_in_scope_endpoint() {
        assert_eq!(
            plan_graphql_introspection(&target(), "/api/graphql", false),
            Err(GraphqlSurfaceError::IntrospectionNotAllowed)
        );
        assert_eq!(
            plan_graphql_introspection(&target(), "https://evil.example/graphql", true),
            Err(GraphqlSurfaceError::InvalidEndpoint)
        );
        let plan = plan_graphql_introspection(&target(), "/api/graphql", true).unwrap();
        assert_eq!(plan.method, HttpMethod::Post);
        assert_eq!(plan.purpose, RequestPurpose::Baseline);
        assert!(plan.body.contains("AegisIntrospection"));
    }

    #[test]
    fn imports_bounded_query_and_mutation_surface_without_defaults() {
        let response = r#"{
          "data":{"__schema":{
            "queryType":{"name":"Query"},
            "mutationType":{"name":"Mutation"},
            "subscriptionType":null,
            "types":[
              {"kind":"OBJECT","name":"Query","fields":[
                {"name":"health","args":[],"type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"String"}}},
                {"name":"user","args":[{"name":"apiToken","defaultValue":null,"type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"ID"}}}],"type":{"kind":"OBJECT","name":"User"}},
                {"name":"locale","args":[{"name":"lang","defaultValue":"\"ko\"","type":{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"String"}}}],"type":{"kind":"SCALAR","name":"String"}}
              ]},
              {"kind":"OBJECT","name":"Mutation","fields":[
                {"name":"deleteUser","args":[],"type":{"kind":"SCALAR","name":"Boolean"}}
              ]},
              {"kind":"OBJECT","name":"User","fields":[]}
            ]
          }}
        }"#;
        let plan = plan_graphql_introspection(&target(), "/api/graphql", true).unwrap();
        let surface = import_graphql_introspection(
            plan.endpoint,
            response,
            GraphqlIntrospectionLimits::default(),
        )
        .unwrap();
        assert_eq!(surface.fields.len(), 4);
        let health = surface
            .fields
            .iter()
            .find(|field| field.name == "health")
            .unwrap();
        assert!(health.automatic_execution_allowed);
        assert_eq!(health.return_type, "String!");
        let user = surface
            .fields
            .iter()
            .find(|field| field.name == "user")
            .unwrap();
        assert!(!user.automatic_execution_allowed);
        assert!(user.arguments[0].required);
        assert!(user.arguments[0].sensitive);
        let locale = surface
            .fields
            .iter()
            .find(|field| field.name == "locale")
            .unwrap();
        assert!(locale.automatic_execution_allowed);
        assert!(locale.arguments[0].has_default);
        assert!(!format!("{surface:?}").contains("ko"));
        let mutation = surface
            .fields
            .iter()
            .find(|field| field.kind == GraphqlOperationKind::Mutation)
            .unwrap();
        assert!(!mutation.automatic_execution_allowed);
    }

    #[test]
    fn rejects_error_response_and_operation_limit() {
        let plan = plan_graphql_introspection(&target(), "/api/graphql", true).unwrap();
        assert_eq!(
            import_graphql_introspection(
                plan.endpoint.clone(),
                r#"{"errors":[{"message":"disabled"}]}"#,
                GraphqlIntrospectionLimits::default(),
            ),
            Err(GraphqlSurfaceError::ResponseContainsErrors)
        );
        let response = r#"{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"a","args":[],"type":{"kind":"SCALAR","name":"String"}},{"name":"b","args":[],"type":{"kind":"SCALAR","name":"String"}}]}]}}}"#;
        let limits = GraphqlIntrospectionLimits {
            max_operations: 1,
            ..GraphqlIntrospectionLimits::default()
        };
        assert_eq!(
            import_graphql_introspection(plan.endpoint, response, limits),
            Err(GraphqlSurfaceError::TooManyOperations)
        );
    }
}
