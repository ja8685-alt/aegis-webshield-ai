use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use url::Url;

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];
const MAX_ENDPOINTS: usize = 5000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiEndpoint {
    pub method: String,
    pub path: String,
    pub url: String,
    pub operation_id: Option<String>,
    pub parameters: Vec<OpenApiParameter>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub security_requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiParameter {
    pub name: String,
    pub location: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiImportResult {
    pub title: Option<String>,
    pub version: Option<String>,
    pub base_url: String,
    pub endpoints: Vec<OpenApiEndpoint>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OpenApiImportError {
    #[error("OpenAPI document is empty")]
    EmptyDocument,
    #[error("OpenAPI document is not valid JSON or YAML")]
    InvalidDocument,
    #[error("OpenAPI document must declare version 3.x")]
    UnsupportedVersion,
    #[error("OpenAPI document does not include a usable HTTP or HTTPS server URL")]
    MissingServerUrl,
    #[error("OpenAPI document has too many endpoints")]
    TooManyEndpoints,
}

pub fn import_openapi_document(
    document: &str,
    override_base_url: Option<&str>,
) -> Result<OpenApiImportResult, OpenApiImportError> {
    if document.trim().is_empty() {
        return Err(OpenApiImportError::EmptyDocument);
    }

    let value = parse_document(document)?;
    validate_openapi_version(&value)?;
    let base_url = resolve_base_url(&value, override_base_url)?;
    let title = value
        .pointer("/info/title")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let version = value
        .pointer("/info/version")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let endpoints = read_endpoints(&value, &base_url)?;

    Ok(OpenApiImportResult {
        title,
        version,
        base_url,
        endpoints,
    })
}

fn parse_document(document: &str) -> Result<Value, OpenApiImportError> {
    let document = document.trim_start_matches('\u{feff}');
    serde_json::from_str(document)
        .or_else(|_| serde_yaml::from_str(document))
        .map_err(|_| OpenApiImportError::InvalidDocument)
}

fn validate_openapi_version(value: &Value) -> Result<(), OpenApiImportError> {
    let Some(version) = value.get("openapi").and_then(Value::as_str) else {
        return Err(OpenApiImportError::UnsupportedVersion);
    };
    if version.starts_with("3.") {
        Ok(())
    } else {
        Err(OpenApiImportError::UnsupportedVersion)
    }
}

fn resolve_base_url(
    value: &Value,
    override_base_url: Option<&str>,
) -> Result<String, OpenApiImportError> {
    if let Some(base_url) = override_base_url {
        return normalize_base_url(base_url);
    }

    let Some(servers) = value.get("servers").and_then(Value::as_array) else {
        return Err(OpenApiImportError::MissingServerUrl);
    };
    servers
        .iter()
        .filter_map(|server| server_url_with_default_variables(server))
        .find_map(|url| normalize_base_url(&url).ok())
        .ok_or(OpenApiImportError::MissingServerUrl)
}

fn server_url_with_default_variables(server: &Value) -> Option<String> {
    let mut url = server.get("url")?.as_str()?.to_string();
    let Some(variables) = server.get("variables").and_then(Value::as_object) else {
        return Some(url);
    };

    for (name, variable) in variables {
        let default_value = variable.get("default")?.as_str()?;
        url = url.replace(&format!("{{{name}}}"), default_value);
    }
    Some(url)
}

fn normalize_base_url(value: &str) -> Result<String, OpenApiImportError> {
    let url = Url::parse(value.trim()).map_err(|_| OpenApiImportError::MissingServerUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(OpenApiImportError::MissingServerUrl);
    }
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn read_endpoints(
    value: &Value,
    base_url: &str,
) -> Result<Vec<OpenApiEndpoint>, OpenApiImportError> {
    let Some(paths) = value.get("paths").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let base = Url::parse(base_url).map_err(|_| OpenApiImportError::MissingServerUrl)?;
    let mut endpoints = Vec::new();

    for (path, path_item) in paths {
        let path_item = resolve_local_ref(value, path_item).unwrap_or(path_item);
        let Some(path_item) = path_item.as_object() else {
            continue;
        };
        let path_parameters = read_parameters(value, path_item.get("parameters"));

        for method in HTTP_METHODS {
            let Some(operation) = path_item.get(*method).and_then(Value::as_object) else {
                continue;
            };
            if endpoints.len() >= MAX_ENDPOINTS {
                return Err(OpenApiImportError::TooManyEndpoints);
            }

            let mut parameters = path_parameters.clone();
            parameters.extend(read_parameters(value, operation.get("parameters")));
            let security_source = operation.get("security").or_else(|| value.get("security"));
            endpoints.push(OpenApiEndpoint {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                url: join_url(&base, path),
                operation_id: operation
                    .get("operationId")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                parameters,
                tags: read_string_array(operation.get("tags")),
                security_requirements: read_security_requirement_names(security_source),
            });
        }
    }

    endpoints.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.method.cmp(&right.method))
    });
    Ok(endpoints)
}

fn read_parameters(root: &Value, value: Option<&Value>) -> Vec<OpenApiParameter> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|parameter| {
            let parameter = resolve_local_ref(root, parameter).unwrap_or(parameter);
            Some(OpenApiParameter {
                name: parameter.get("name")?.as_str()?.to_string(),
                location: parameter.get("in")?.as_str()?.to_string(),
                required: parameter
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect()
}

fn read_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .collect()
}

fn read_security_requirement_names(value: Option<&Value>) -> Vec<String> {
    let mut names = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .flat_map(|requirement| requirement.keys().cloned())
        .filter(|name| !name.trim().is_empty())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn resolve_local_ref<'a>(root: &'a Value, value: &'a Value) -> Option<&'a Value> {
    let reference = value.get("$ref")?.as_str()?;
    if reference == "#" {
        return Some(root);
    }
    let pointer = reference.strip_prefix('#')?;
    root.pointer(pointer)
}

fn join_url(base: &Url, path: &str) -> String {
    let mut url = base.clone();
    let mut joined_path = base.path().trim_end_matches('/').to_string();
    joined_path.push('/');
    joined_path.push_str(path.trim_start_matches('/'));
    url.set_path(&joined_path);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_json_openapi_endpoints() {
        let document = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Store API", "version": "1.2.0" },
            "servers": [{ "url": "https://api.example.com/v1" }],
            "paths": {
                "/pets/{petId}": {
                    "parameters": [
                        { "name": "traceId", "in": "header" }
                    ],
                    "get": {
                        "operationId": "getPet",
                        "parameters": [
                            { "name": "petId", "in": "path", "required": true }
                        ]
                    },
                    "post": {
                        "operationId": "updatePet"
                    }
                }
            }
        }"#;

        let result = import_openapi_document(document, None).expect("import");

        assert_eq!(result.title, Some("Store API".to_string()));
        assert_eq!(result.version, Some("1.2.0".to_string()));
        assert_eq!(result.base_url, "https://api.example.com/v1");
        assert_eq!(result.endpoints.len(), 2);
        assert_eq!(result.endpoints[0].method, "GET");
        assert_eq!(
            result.endpoints[0].url,
            "https://api.example.com/v1/pets/%7BpetId%7D"
        );
        assert_eq!(result.endpoints[0].operation_id, Some("getPet".to_string()));
        assert_eq!(result.endpoints[0].parameters.len(), 2);
    }

    #[test]
    fn imports_yaml_with_override_base_url() {
        let document = r#"
openapi: 3.1.0
info:
  title: YAML API
  version: 0.1.0
paths:
  /health:
    get:
      operationId: health
"#;

        let result = import_openapi_document(document, Some("https://staging.example.com/api"))
            .expect("import");

        assert_eq!(result.base_url, "https://staging.example.com/api");
        assert_eq!(result.endpoints[0].method, "GET");
        assert_eq!(
            result.endpoints[0].url,
            "https://staging.example.com/api/health"
        );
    }

    #[test]
    fn normalizes_server_variables_with_defaults() {
        let document = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Variable API", "version": "1" },
            "servers": [{
                "url": "https://{environment}.example.com/{basePath}",
                "variables": {
                    "environment": { "default": "staging" },
                    "basePath": { "default": "v2" }
                }
            }],
            "paths": {
                "/users": { "get": { "operationId": "listUsers" } }
            }
        }"#;

        let result = import_openapi_document(document, None).expect("import");

        assert_eq!(result.base_url, "https://staging.example.com/v2");
        assert_eq!(
            result.endpoints[0].url,
            "https://staging.example.com/v2/users"
        );
    }

    #[test]
    fn resolves_local_parameter_and_path_item_refs() {
        let document = r##"{
            "openapi": "3.1.0",
            "info": { "title": "Refs API", "version": "1" },
            "servers": [{ "url": "https://api.example.com" }],
            "components": {
                "parameters": {
                    "TraceId": { "name": "traceId", "in": "header" },
                    "UserId": { "name": "userId", "in": "path", "required": true }
                },
                "pathItems": {
                    "UserItem": {
                        "parameters": [{ "$ref": "#/components/parameters/TraceId" }],
                        "get": {
                            "operationId": "getUser",
                            "parameters": [{ "$ref": "#/components/parameters/UserId" }]
                        }
                    }
                }
            },
            "paths": {
                "/users/{userId}": { "$ref": "#/components/pathItems/UserItem" }
            }
        }"##;

        let result = import_openapi_document(document, None).expect("import");

        assert_eq!(result.endpoints.len(), 1);
        assert_eq!(
            result.endpoints[0].operation_id,
            Some("getUser".to_string())
        );
        assert_eq!(
            result.endpoints[0].parameters,
            vec![
                OpenApiParameter {
                    name: "traceId".to_string(),
                    location: "header".to_string(),
                    required: false,
                },
                OpenApiParameter {
                    name: "userId".to_string(),
                    location: "path".to_string(),
                    required: true,
                },
            ]
        );
    }

    #[test]
    fn preserves_tags_and_security_requirement_names() {
        let document = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Metadata API", "version": "1" },
            "servers": [{ "url": "https://api.example.com" }],
            "security": [{ "ApiKeyAuth": [] }],
            "paths": {
                "/payments": {
                    "get": {
                        "operationId": "listPayments",
                        "tags": ["billing", "reports"],
                        "security": [{ "OAuth2": ["payments:read"] }, { "ApiKeyAuth": [] }]
                    }
                },
                "/health": {
                    "get": {
                        "operationId": "health",
                        "tags": ["system"]
                    }
                }
            }
        }"#;

        let result = import_openapi_document(document, None).expect("import");
        let health = result
            .endpoints
            .iter()
            .find(|endpoint| endpoint.path == "/health")
            .expect("health endpoint");
        let payments = result
            .endpoints
            .iter()
            .find(|endpoint| endpoint.path == "/payments")
            .expect("payments endpoint");

        assert_eq!(health.tags, vec!["system".to_string()]);
        assert_eq!(health.security_requirements, vec!["ApiKeyAuth".to_string()]);
        assert_eq!(
            payments.tags,
            vec!["billing".to_string(), "reports".to_string()]
        );
        assert_eq!(
            payments.security_requirements,
            vec!["ApiKeyAuth".to_string(), "OAuth2".to_string()]
        );
    }

    #[test]
    fn rejects_openapi_2_documents() {
        let document = r#"{ "swagger": "2.0", "paths": {} }"#;

        assert_eq!(
            import_openapi_document(document, Some("https://example.com")),
            Err(OpenApiImportError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_non_http_servers() {
        let document = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Bad", "version": "1" },
            "servers": [{ "url": "file:///tmp/api" }],
            "paths": {}
        }"#;

        assert_eq!(
            import_openapi_document(document, None),
            Err(OpenApiImportError::MissingServerUrl)
        );
    }

    #[test]
    fn imports_yaml_with_utf8_bom() {
        let document = "\u{feff}openapi: 3.0.3\ninfo:\n  title: BOM API\n  version: 1\npaths:\n  /health:\n    get: {}\n";

        let result =
            import_openapi_document(document, Some("https://api.example.com")).expect("import");

        assert_eq!(result.title, Some("BOM API".to_string()));
        assert_eq!(result.endpoints.len(), 1);
    }

    #[test]
    fn rejects_documents_that_exceed_endpoint_limit() {
        let mut paths = String::new();
        for index in 0..=MAX_ENDPOINTS {
            paths.push_str(&format!(r#""/items/{index}": {{"get": {{}}}},"#));
        }
        paths.pop();
        let document = format!(
            r#"{{
                "openapi": "3.0.3",
                "info": {{ "title": "Large API", "version": "1" }},
                "servers": [{{ "url": "https://api.example.com" }}],
                "paths": {{{paths}}}
            }}"#
        );

        assert_eq!(
            import_openapi_document(&document, None),
            Err(OpenApiImportError::TooManyEndpoints)
        );
    }
}
