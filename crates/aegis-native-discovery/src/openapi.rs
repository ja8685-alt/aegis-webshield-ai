use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

use aegis_native_engine::{ApprovedTarget, MAX_URL_BYTES};
use serde_json::Value;
use url::Url;

use crate::{canonicalize_url, CanonicalUrl, CanonicalizationOutcome};

const HARD_MAX_SPEC_BYTES: usize = 2 * 1024 * 1024;
const HARD_MAX_VALUE_NODES: usize = 100_000;
const HARD_MAX_VALUE_DEPTH: usize = 64;
const HARD_MAX_PATHS: usize = 300;
const HARD_MAX_OPERATIONS: usize = 500;
const HARD_MAX_PARAMETERS: usize = 64;
const HARD_MAX_CONTENT_TYPES: usize = 16;
const MAX_NAME_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenApiDocumentFormat {
    Json,
    Yaml,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenApiImportLimits {
    pub max_spec_bytes: usize,
    pub max_value_nodes: usize,
    pub max_value_depth: usize,
    pub max_paths: usize,
    pub max_operations: usize,
    pub max_parameters_per_operation: usize,
}

impl Default for OpenApiImportLimits {
    fn default() -> Self {
        Self {
            max_spec_bytes: HARD_MAX_SPEC_BYTES,
            max_value_nodes: HARD_MAX_VALUE_NODES,
            max_value_depth: HARD_MAX_VALUE_DEPTH,
            max_paths: HARD_MAX_PATHS,
            max_operations: HARD_MAX_OPERATIONS,
            max_parameters_per_operation: HARD_MAX_PARAMETERS,
        }
    }
}

impl OpenApiImportLimits {
    fn validate(&self) -> Result<(), OpenApiImportError> {
        if self.max_spec_bytes == 0
            || self.max_spec_bytes > HARD_MAX_SPEC_BYTES
            || self.max_value_nodes == 0
            || self.max_value_nodes > HARD_MAX_VALUE_NODES
            || self.max_value_depth == 0
            || self.max_value_depth > HARD_MAX_VALUE_DEPTH
            || self.max_paths == 0
            || self.max_paths > HARD_MAX_PATHS
            || self.max_operations == 0
            || self.max_operations > HARD_MAX_OPERATIONS
            || self.max_parameters_per_operation == 0
            || self.max_parameters_per_operation > HARD_MAX_PARAMETERS
        {
            return Err(OpenApiImportError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenApiImportError {
    InvalidLimits,
    InvalidTarget,
    InvalidSourceUrl,
    DocumentTooLarge,
    ParseFailed,
    UnsupportedVersion,
    StructureLimitExceeded,
    TooManyPaths,
    TooManyOperations,
    TooManyParameters,
    NoInScopeServer,
    ExternalReferenceForbidden,
    InvalidReference,
    InvalidOperation,
}

impl Display for OpenApiImportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "OpenAPI import limits are invalid",
            Self::InvalidTarget => "approved target is invalid",
            Self::InvalidSourceUrl => "OpenAPI source URL is invalid",
            Self::DocumentTooLarge => "OpenAPI document exceeded the size limit",
            Self::ParseFailed => "OpenAPI document could not be parsed",
            Self::UnsupportedVersion => "only OpenAPI 3.0 and 3.1 are supported",
            Self::StructureLimitExceeded => "OpenAPI structure exceeded depth or node limits",
            Self::TooManyPaths => "OpenAPI path limit exceeded",
            Self::TooManyOperations => "OpenAPI operation limit exceeded",
            Self::TooManyParameters => "OpenAPI parameter limit exceeded",
            Self::NoInScopeServer => "OpenAPI has no server inside the approved target",
            Self::ExternalReferenceForbidden => "external OpenAPI references are forbidden",
            Self::InvalidReference => "OpenAPI local reference is invalid",
            Self::InvalidOperation => "OpenAPI operation contract is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OpenApiImportError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiMethod {
    Get,
    Head,
    Options,
    Post,
    Put,
    Patch,
    Delete,
    Trace,
}

impl ApiMethod {
    pub fn automatic_execution_allowed(self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Trace => "TRACE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ApiParameter {
    pub name: String,
    pub location: ApiParameterLocation,
    pub required: bool,
    pub schema_type: Option<String>,
    pub schema_format: Option<String>,
    pub sensitive: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiAuthKind {
    HttpBasic,
    HttpBearer,
    ApiKeyHeader,
    ApiKeyQuery,
    ApiKeyCookie,
    OAuth2,
    OpenIdConnect,
    MutualTls,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiAuthScheme {
    pub name: String,
    pub kind: ApiAuthKind,
    pub credential_name: Option<String>,
    pub worker_injection_supported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestBodyContract {
    pub required: bool,
    pub content_types: Vec<String>,
    pub schema_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiOperation {
    pub operation_id: Option<String>,
    pub method: ApiMethod,
    pub url: CanonicalUrl,
    pub route_template: bool,
    pub parameters: Vec<ApiParameter>,
    pub request_body: Option<RequestBodyContract>,
    pub security_schemes: Vec<String>,
    pub automatic_execution_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedOpenApi {
    pub version: String,
    pub operations: Vec<ApiOperation>,
    pub auth_schemes: Vec<ApiAuthScheme>,
    pub ignored_out_of_scope_servers: usize,
}

pub fn import_openapi(
    target: &ApprovedTarget,
    source_url: &str,
    document: &str,
    format: OpenApiDocumentFormat,
    limits: OpenApiImportLimits,
) -> Result<ImportedOpenApi, OpenApiImportError> {
    limits.validate()?;
    target
        .validate()
        .map_err(|_| OpenApiImportError::InvalidTarget)?;
    if !target.contains_url(source_url) {
        return Err(OpenApiImportError::InvalidSourceUrl);
    }
    if document.len() > limits.max_spec_bytes {
        return Err(OpenApiImportError::DocumentTooLarge);
    }
    let root: Value = match format {
        OpenApiDocumentFormat::Json => {
            serde_json::from_str(document).map_err(|_| OpenApiImportError::ParseFailed)?
        }
        OpenApiDocumentFormat::Yaml => {
            yaml_serde::from_str(document).map_err(|_| OpenApiImportError::ParseFailed)?
        }
    };
    validate_structure(&root, limits.max_value_nodes, limits.max_value_depth)?;
    validate_references(&root)?;
    let root_object = root.as_object().ok_or(OpenApiImportError::ParseFailed)?;
    let version = root_object
        .get("openapi")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("3.0.") || value.starts_with("3.1."))
        .ok_or(OpenApiImportError::UnsupportedVersion)?
        .to_string();
    let paths = root_object
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(OpenApiImportError::InvalidOperation)?;
    if paths.len() > limits.max_paths {
        return Err(OpenApiImportError::TooManyPaths);
    }

    let root_security = security_names(root_object.get("security"))?;
    let root_servers = root_object.get("servers").and_then(Value::as_array);
    let (default_base, mut ignored_out_of_scope_servers) =
        select_in_scope_server(target, source_url, root_servers)?;
    let auth_schemes = import_auth_schemes(&root)?;
    let mut operations = Vec::new();

    for (path, raw_path_item) in paths {
        if !path.starts_with('/') || path.len() > MAX_URL_BYTES || path.contains(['\r', '\n']) {
            return Err(OpenApiImportError::InvalidOperation);
        }
        let path_item = resolve_reference(&root, raw_path_item, "#/components/pathItems/")?;
        let path_object = path_item
            .as_object()
            .ok_or(OpenApiImportError::InvalidOperation)?;
        let path_parameters = parameter_values(path_object.get("parameters"))?;
        let path_servers = path_object.get("servers").and_then(Value::as_array);

        for (method_name, method) in method_entries() {
            let Some(raw_operation) = path_object.get(method_name) else {
                continue;
            };
            if operations.len() >= limits.max_operations {
                return Err(OpenApiImportError::TooManyOperations);
            }
            let operation = raw_operation
                .as_object()
                .ok_or(OpenApiImportError::InvalidOperation)?;
            let operation_servers = operation.get("servers").and_then(Value::as_array);
            let base = if operation_servers.is_some() {
                let (base, ignored) =
                    select_in_scope_server(target, source_url, operation_servers)?;
                ignored_out_of_scope_servers += ignored;
                base
            } else if path_servers.is_some() {
                let (base, ignored) = select_in_scope_server(target, source_url, path_servers)?;
                ignored_out_of_scope_servers += ignored;
                base
            } else {
                default_base.clone()
            };
            let absolute = append_openapi_path(&base, path)?;
            let CanonicalizationOutcome::Accepted(url) =
                canonicalize_url(target, source_url, &absolute)
                    .map_err(|_| OpenApiImportError::InvalidOperation)?
            else {
                return Err(OpenApiImportError::NoInScopeServer);
            };

            let mut parameters = BTreeMap::<(ApiParameterLocation, String), ApiParameter>::new();
            for parameter in path_parameters
                .iter()
                .chain(parameter_values(operation.get("parameters"))?.iter())
            {
                let imported = import_parameter(&root, parameter)?;
                parameters.insert((imported.location, imported.name.clone()), imported);
            }
            if parameters.len() > limits.max_parameters_per_operation {
                return Err(OpenApiImportError::TooManyParameters);
            }
            let operation_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .map(validated_name)
                .transpose()?;
            let request_body = operation
                .get("requestBody")
                .map(|value| import_request_body(&root, value))
                .transpose()?;
            let security_schemes = if operation.contains_key("security") {
                security_names(operation.get("security"))?
            } else {
                root_security.clone()
            };
            let route_template = path
                .split('/')
                .any(|segment| segment.starts_with('{') && segment.ends_with('}'));
            let parameters = parameters.into_values().collect::<Vec<_>>();
            let has_unbound_required_parameter =
                parameters.iter().any(|parameter| parameter.required);
            operations.push(ApiOperation {
                operation_id,
                method,
                url,
                route_template,
                parameters,
                request_body,
                security_schemes,
                automatic_execution_allowed: method.automatic_execution_allowed()
                    && !route_template
                    && !has_unbound_required_parameter,
            });
        }
    }
    operations.sort_by(|left, right| {
        (left.url.dedup_key(), left.method.name())
            .cmp(&(right.url.dedup_key(), right.method.name()))
    });

    Ok(ImportedOpenApi {
        version,
        operations,
        auth_schemes,
        ignored_out_of_scope_servers,
    })
}

fn validate_structure(
    root: &Value,
    max_nodes: usize,
    max_depth: usize,
) -> Result<(), OpenApiImportError> {
    let mut stack = vec![(root, 1usize)];
    let mut nodes = 0usize;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > max_nodes || depth > max_depth {
            return Err(OpenApiImportError::StructureLimitExceeded);
        }
        match value {
            Value::Array(values) => stack.extend(values.iter().map(|value| (value, depth + 1))),
            Value::Object(values) => stack.extend(values.values().map(|value| (value, depth + 1))),
            Value::String(value) if value.len() > HARD_MAX_SPEC_BYTES => {
                return Err(OpenApiImportError::StructureLimitExceeded);
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_references(root: &Value) -> Result<(), OpenApiImportError> {
    let mut stack = vec![root];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(values) => stack.extend(values),
            Value::Object(values) => {
                if let Some(reference) = values.get("$ref").and_then(Value::as_str) {
                    if !reference.starts_with('#') {
                        return Err(OpenApiImportError::ExternalReferenceForbidden);
                    }
                    if !reference.starts_with("#/") || reference.len() > MAX_NAME_BYTES {
                        return Err(OpenApiImportError::InvalidReference);
                    }
                }
                stack.extend(values.values());
            }
            _ => {}
        }
    }
    Ok(())
}

fn method_entries() -> [(&'static str, ApiMethod); 8] {
    [
        ("get", ApiMethod::Get),
        ("head", ApiMethod::Head),
        ("options", ApiMethod::Options),
        ("post", ApiMethod::Post),
        ("put", ApiMethod::Put),
        ("patch", ApiMethod::Patch),
        ("delete", ApiMethod::Delete),
        ("trace", ApiMethod::Trace),
    ]
}

fn select_in_scope_server(
    target: &ApprovedTarget,
    source_url: &str,
    servers: Option<&Vec<Value>>,
) -> Result<(String, usize), OpenApiImportError> {
    let Some(servers) = servers.filter(|servers| !servers.is_empty()) else {
        return Ok((format!("{}{}", target.origin, target.path_prefix), 0));
    };
    let source = Url::parse(source_url).map_err(|_| OpenApiImportError::InvalidSourceUrl)?;
    let mut ignored = 0usize;
    for server in servers {
        let Some(server_object) = server.as_object() else {
            ignored += 1;
            continue;
        };
        let Some(template) = server_object.get("url").and_then(Value::as_str) else {
            ignored += 1;
            continue;
        };
        let Some(expanded) = expand_server_variables(template, server_object.get("variables"))
        else {
            ignored += 1;
            continue;
        };
        let Ok(resolved) = source.join(&expanded) else {
            ignored += 1;
            continue;
        };
        if target.contains_url(resolved.as_str()) {
            return Ok((resolved.to_string(), ignored));
        }
        ignored += 1;
    }
    Err(OpenApiImportError::NoInScopeServer)
}

fn expand_server_variables(template: &str, variables: Option<&Value>) -> Option<String> {
    if template.len() > MAX_URL_BYTES || template.contains(['\r', '\n', '\0']) {
        return None;
    }
    let mut expanded = template.to_string();
    let variables = variables.and_then(Value::as_object);
    while let Some(start) = expanded.find('{') {
        let end = expanded[start + 1..].find('}')? + start + 1;
        let name = &expanded[start + 1..end];
        let default = variables?
            .get(name)?
            .get("default")?
            .as_str()
            .filter(|value| value.len() <= MAX_NAME_BYTES && !value.contains(['\r', '\n']))?;
        expanded.replace_range(start..=end, default);
    }
    if expanded.contains('}') {
        return None;
    }
    Some(expanded)
}

fn append_openapi_path(base: &str, path: &str) -> Result<String, OpenApiImportError> {
    let mut url = Url::parse(base).map_err(|_| OpenApiImportError::InvalidOperation)?;
    let base_path = url.path().trim_end_matches('/');
    let operation_path = path.trim_start_matches('/');
    let combined = if base_path.is_empty() {
        format!("/{operation_path}")
    } else if operation_path.is_empty() {
        base_path.to_string()
    } else {
        format!("{base_path}/{operation_path}")
    };
    url.set_path(&combined);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn parameter_values(value: Option<&Value>) -> Result<Vec<&Value>, OpenApiImportError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) if values.len() <= HARD_MAX_PARAMETERS => {
            Ok(values.iter().collect())
        }
        _ => Err(OpenApiImportError::TooManyParameters),
    }
}

fn import_parameter(root: &Value, value: &Value) -> Result<ApiParameter, OpenApiImportError> {
    let value = resolve_reference(root, value, "#/components/parameters/")?;
    let object = value
        .as_object()
        .ok_or(OpenApiImportError::InvalidOperation)?;
    let name = validated_name(
        object
            .get("name")
            .and_then(Value::as_str)
            .ok_or(OpenApiImportError::InvalidOperation)?,
    )?;
    let location = match object.get("in").and_then(Value::as_str) {
        Some("path") => ApiParameterLocation::Path,
        Some("query") => ApiParameterLocation::Query,
        Some("header") => ApiParameterLocation::Header,
        Some("cookie") => ApiParameterLocation::Cookie,
        _ => return Err(OpenApiImportError::InvalidOperation),
    };
    let schema = object.get("schema").and_then(Value::as_object);
    let schema_type = schema
        .and_then(|schema| schema.get("type"))
        .and_then(single_schema_type)
        .map(validated_name)
        .transpose()?;
    let schema_format = schema
        .and_then(|schema| schema.get("format"))
        .and_then(Value::as_str)
        .map(validated_name)
        .transpose()?;
    let required = location == ApiParameterLocation::Path
        || object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    Ok(ApiParameter {
        sensitive: is_sensitive_name(&name),
        name,
        location,
        required,
        schema_type,
        schema_format,
    })
}

fn import_request_body(
    root: &Value,
    value: &Value,
) -> Result<RequestBodyContract, OpenApiImportError> {
    let value = resolve_reference(root, value, "#/components/requestBodies/")?;
    let object = value
        .as_object()
        .ok_or(OpenApiImportError::InvalidOperation)?;
    let content = object
        .get("content")
        .and_then(Value::as_object)
        .ok_or(OpenApiImportError::InvalidOperation)?;
    if content.len() > HARD_MAX_CONTENT_TYPES {
        return Err(OpenApiImportError::InvalidOperation);
    }
    let mut content_types = content
        .keys()
        .map(|value| validated_name(value))
        .collect::<Result<Vec<_>, _>>()?;
    content_types.sort();
    let schema_ref = content
        .values()
        .filter_map(Value::as_object)
        .filter_map(|media| media.get("schema"))
        .filter_map(Value::as_object)
        .filter_map(|schema| schema.get("$ref"))
        .filter_map(Value::as_str)
        .next()
        .map(|reference| {
            if reference.starts_with("#/components/schemas/") {
                validated_name(reference)
            } else if reference.starts_with('#') {
                Err(OpenApiImportError::InvalidReference)
            } else {
                Err(OpenApiImportError::ExternalReferenceForbidden)
            }
        })
        .transpose()?;
    Ok(RequestBodyContract {
        required: object
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        content_types,
        schema_ref,
    })
}

fn import_auth_schemes(root: &Value) -> Result<Vec<ApiAuthScheme>, OpenApiImportError> {
    let Some(schemes) = root
        .pointer("/components/securitySchemes")
        .and_then(Value::as_object)
    else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for (name, raw_scheme) in schemes {
        let scheme = resolve_reference(root, raw_scheme, "#/components/securitySchemes/")?;
        let object = scheme
            .as_object()
            .ok_or(OpenApiImportError::InvalidOperation)?;
        let (kind, credential_name, supported) = match object.get("type").and_then(Value::as_str) {
            Some("http") => match object.get("scheme").and_then(Value::as_str) {
                Some(value) if value.eq_ignore_ascii_case("bearer") => {
                    (ApiAuthKind::HttpBearer, None, true)
                }
                Some(value) if value.eq_ignore_ascii_case("basic") => {
                    (ApiAuthKind::HttpBasic, None, false)
                }
                _ => (ApiAuthKind::Unsupported, None, false),
            },
            Some("apiKey") => {
                let credential_name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .map(validated_name)
                    .transpose()?;
                let kind = match object.get("in").and_then(Value::as_str) {
                    Some("header") => ApiAuthKind::ApiKeyHeader,
                    Some("query") => ApiAuthKind::ApiKeyQuery,
                    Some("cookie") => ApiAuthKind::ApiKeyCookie,
                    _ => ApiAuthKind::Unsupported,
                };
                let supported =
                    matches!(kind, ApiAuthKind::ApiKeyHeader | ApiAuthKind::ApiKeyCookie);
                (kind, credential_name, supported)
            }
            Some("oauth2") => (ApiAuthKind::OAuth2, None, false),
            Some("openIdConnect") => (ApiAuthKind::OpenIdConnect, None, false),
            Some("mutualTLS") => (ApiAuthKind::MutualTls, None, false),
            _ => (ApiAuthKind::Unsupported, None, false),
        };
        result.push(ApiAuthScheme {
            name: validated_name(name)?,
            kind,
            credential_name,
            worker_injection_supported: supported,
        });
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

fn security_names(value: Option<&Value>) -> Result<Vec<String>, OpenApiImportError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let requirements = value
        .as_array()
        .ok_or(OpenApiImportError::InvalidOperation)?;
    let mut names = BTreeSet::new();
    for requirement in requirements {
        let object = requirement
            .as_object()
            .ok_or(OpenApiImportError::InvalidOperation)?;
        for name in object.keys() {
            names.insert(validated_name(name)?);
        }
    }
    Ok(names.into_iter().collect())
}

fn resolve_reference<'a>(
    root: &'a Value,
    value: &'a Value,
    allowed_prefix: &str,
) -> Result<&'a Value, OpenApiImportError> {
    let Some(reference) = value
        .as_object()
        .and_then(|object| object.get("$ref"))
        .and_then(Value::as_str)
    else {
        return Ok(value);
    };
    if !reference.starts_with('#') {
        return Err(OpenApiImportError::ExternalReferenceForbidden);
    }
    if !reference.starts_with(allowed_prefix) {
        return Err(OpenApiImportError::InvalidReference);
    }
    let pointer = reference
        .strip_prefix('#')
        .ok_or(OpenApiImportError::InvalidReference)?;
    let resolved = root
        .pointer(pointer)
        .ok_or(OpenApiImportError::InvalidReference)?;
    if resolved.get("$ref").is_some() {
        return Err(OpenApiImportError::InvalidReference);
    }
    Ok(resolved)
}

fn single_schema_type(value: &Value) -> Option<&str> {
    match value {
        Value::String(value) => Some(value),
        Value::Array(values) => values.iter().find_map(|value| match value.as_str() {
            Some("null") | None => None,
            value => value,
        }),
        _ => None,
    }
}

fn validated_name(value: &str) -> Result<String, OpenApiImportError> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES || value.contains(['\r', '\n', '\0']) {
        return Err(OpenApiImportError::InvalidOperation);
    }
    Ok(value.to_string())
}

fn is_sensitive_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase().replace('-', "_");
    lower.contains("token")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower == "key"
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::ApprovedTarget;

    use super::{
        import_openapi, ApiAuthKind, ApiMethod, ApiParameterLocation, OpenApiDocumentFormat,
        OpenApiImportError, OpenApiImportLimits,
    };

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://api.example.com", "/api").unwrap()
    }

    #[test]
    fn imports_openapi_30_operations_parameters_body_and_auth() {
        let document = r##"{
          "openapi":"3.0.3",
          "servers":[{"url":"https://evil.example/v1"},{"url":"/api/v1"}],
          "security":[{"bearerAuth":[]}],
          "paths":{
            "/users/{id}":{
              "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
              "get":{"operationId":"getUser","parameters":[{"name":"api_token","in":"query","schema":{"type":"string"}}]},
              "post":{"operationId":"updateUser","requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/User"}}}}}
            }
          },
          "components":{
            "schemas":{"User":{"type":"object"}},
            "securitySchemes":{
              "bearerAuth":{"type":"http","scheme":"bearer"},
              "apiKey":{"type":"apiKey","in":"header","name":"X-API-Key"}
            }
          }
        }"##;
        let imported = import_openapi(
            &target(),
            "https://api.example.com/api/openapi.json",
            document,
            OpenApiDocumentFormat::Json,
            OpenApiImportLimits::default(),
        )
        .unwrap();

        assert_eq!(imported.version, "3.0.3");
        assert_eq!(imported.operations.len(), 2);
        assert_eq!(imported.ignored_out_of_scope_servers, 1);
        let get = imported
            .operations
            .iter()
            .find(|operation| operation.method == ApiMethod::Get)
            .unwrap();
        assert_eq!(
            get.url.as_str(),
            "https://api.example.com/api/v1/users/%7Bid%7D"
        );
        assert!(get.route_template);
        assert!(!get.automatic_execution_allowed);
        assert!(get.parameters.iter().any(|parameter| {
            parameter.location == ApiParameterLocation::Query && parameter.sensitive
        }));
        let post = imported
            .operations
            .iter()
            .find(|operation| operation.method == ApiMethod::Post)
            .unwrap();
        assert_eq!(
            post.request_body.as_ref().unwrap().schema_ref.as_deref(),
            Some("#/components/schemas/User")
        );
        assert!(!post.automatic_execution_allowed);
        assert_eq!(imported.auth_schemes[0].kind, ApiAuthKind::ApiKeyHeader);
        assert!(imported.auth_schemes[0].worker_injection_supported);
        assert_eq!(imported.auth_schemes[1].kind, ApiAuthKind::HttpBearer);
    }

    #[test]
    fn imports_openapi_31_yaml_and_server_variables() {
        let document = r#"
openapi: 3.1.0
servers:
  - url: /api/{version}
    variables:
      version:
        default: v2
paths:
  /health:
    get:
      operationId: health
      security: []
      parameters:
        - name: nullable
          in: query
          schema:
            type: [string, "null"]
"#;
        let imported = import_openapi(
            &target(),
            "https://api.example.com/api/openapi.yaml",
            document,
            OpenApiDocumentFormat::Yaml,
            OpenApiImportLimits::default(),
        )
        .unwrap();
        assert_eq!(imported.version, "3.1.0");
        assert_eq!(imported.operations.len(), 1);
        assert_eq!(
            imported.operations[0].url.as_str(),
            "https://api.example.com/api/v2/health"
        );
        assert!(imported.operations[0].automatic_execution_allowed);
        assert!(imported.operations[0].security_schemes.is_empty());
        assert_eq!(
            imported.operations[0].parameters[0].schema_type.as_deref(),
            Some("string")
        );
    }

    #[test]
    fn rejects_external_references_and_out_of_scope_servers() {
        let external_ref = r##"{
          "openapi":"3.0.3",
          "paths":{"/x":{"get":{"parameters":[{"$ref":"https://evil.example/p.json"}]}}}
        }"##;
        assert_eq!(
            import_openapi(
                &target(),
                "https://api.example.com/api/openapi.json",
                external_ref,
                OpenApiDocumentFormat::Json,
                OpenApiImportLimits::default(),
            ),
            Err(OpenApiImportError::ExternalReferenceForbidden)
        );

        let external_server = r#"{
          "openapi":"3.0.3",
          "servers":[{"url":"https://evil.example/api"}],
          "paths":{}
        }"#;
        assert_eq!(
            import_openapi(
                &target(),
                "https://api.example.com/api/openapi.json",
                external_server,
                OpenApiDocumentFormat::Json,
                OpenApiImportLimits::default(),
            ),
            Err(OpenApiImportError::NoInScopeServer)
        );
    }

    #[test]
    fn enforces_path_limit_before_operation_import() {
        let limits = OpenApiImportLimits {
            max_paths: 1,
            ..OpenApiImportLimits::default()
        };
        let document = r#"{"openapi":"3.0.3","paths":{"/a":{},"/b":{}}}"#;
        assert_eq!(
            import_openapi(
                &target(),
                "https://api.example.com/api/openapi.json",
                document,
                OpenApiDocumentFormat::Json,
                limits,
            ),
            Err(OpenApiImportError::TooManyPaths)
        );
    }
}
