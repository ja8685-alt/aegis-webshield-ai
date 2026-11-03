use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

const MAX_FIELD_LEN: usize = 4096;
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_OPENAI_MODEL: &str = "gpt-5.5";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiFixGuideRequest {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub endpoint: String,
    pub evidence: String,
    pub remediation_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiFixGuide {
    pub finding_id: String,
    pub summary: String,
    pub safe_fix_steps: Vec<String>,
    pub verification_steps: Vec<String>,
    pub cautions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AiFixGuideBody {
    summary: String,
    safe_fix_steps: Vec<String>,
    verification_steps: Vec<String>,
    cautions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiProviderConfig {
    pub api_key: String,
    pub model: String,
    pub base_url: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AiGuideError {
    #[error("AI Fix Guide is locked for this plan")]
    FeatureLocked,
    #[error("AI provider key is required")]
    MissingApiKey,
    #[error("AI Fix Guide input is invalid")]
    InvalidInput,
    #[error("AI provider failed: {0}")]
    ProviderFailed(String),
}

pub trait AiFixGuideClient {
    fn generate_fix_guide(&self, request: &AiFixGuideRequest) -> Result<AiFixGuide, AiGuideError>;
}

#[derive(Debug, Clone)]
pub struct OpenAiResponsesClient {
    config: OpenAiProviderConfig,
}

impl OpenAiResponsesClient {
    pub fn new(api_key: String) -> Self {
        Self {
            config: OpenAiProviderConfig {
                api_key,
                model: DEFAULT_OPENAI_MODEL.to_string(),
                base_url: DEFAULT_OPENAI_BASE_URL.to_string(),
            },
        }
    }

    pub fn with_config(config: OpenAiProviderConfig) -> Self {
        Self { config }
    }
}

impl AiFixGuideClient for OpenAiResponsesClient {
    fn generate_fix_guide(&self, request: &AiFixGuideRequest) -> Result<AiFixGuide, AiGuideError> {
        validate_request(request)?;
        validate_api_key(&self.config.api_key)?;
        let prompt = build_fix_guide_prompt(request)?;
        let payload = build_openai_response_payload(&self.config.model, &prompt);
        let url = format!("{}/responses", self.config.base_url.trim_end_matches('/'));
        let response = ureq::post(&url)
            .set(
                "Authorization",
                &format!("Bearer {}", self.config.api_key.trim()),
            )
            .set("Content-Type", "application/json")
            .send_json(payload)
            .map_err(|error| AiGuideError::ProviderFailed(error.to_string()))?;
        let value: Value = response
            .into_json()
            .map_err(|error| AiGuideError::ProviderFailed(error.to_string()))?;
        parse_openai_fix_guide(&value, &request.finding_id)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicFixGuideClient;

impl AiFixGuideClient for DeterministicFixGuideClient {
    fn generate_fix_guide(&self, request: &AiFixGuideRequest) -> Result<AiFixGuide, AiGuideError> {
        validate_request(request)?;
        Ok(AiFixGuide {
            finding_id: request.finding_id.clone(),
            summary: format!(
                "{} on {} should be reviewed with severity {}.",
                request.title,
                redact_secrets(&request.endpoint),
                request.severity
            ),
            safe_fix_steps: vec![
                "Confirm the affected route is owned and in scope.".to_string(),
                redact_secrets(&request.remediation_hint),
                "Apply the change in a staging environment before production rollout.".to_string(),
            ],
            verification_steps: vec![
                "Re-run a passive scan against the approved target.".to_string(),
                "Confirm the original evidence is no longer present.".to_string(),
            ],
            cautions: vec![
                "Do not include secrets, tokens, or customer data in AI prompts.".to_string(),
                "Avoid destructive validation unless explicit authorization exists.".to_string(),
            ],
        })
    }
}

pub fn build_fix_guide_prompt(request: &AiFixGuideRequest) -> Result<String, AiGuideError> {
    validate_request(request)?;
    Ok(format!(
        "Create a safe remediation guide for a web security finding.\n\
        Success criteria: concise summary, safe fix steps, verification steps, and cautions only.\n\
        Scope rule: do not recommend expanding testing beyond the explicitly approved target.\n\
        Finding ID: {}\n\
        Title: {}\n\
        Severity: {}\n\
        Endpoint: {}\n\
        Evidence: {}\n\
        Remediation hint: {}",
        redact_secrets(&request.finding_id),
        redact_secrets(&request.title),
        redact_secrets(&request.severity),
        redact_secrets(&request.endpoint),
        redact_secrets(&request.evidence),
        redact_secrets(&request.remediation_hint),
    ))
}

pub fn build_openai_response_payload(model: &str, prompt: &str) -> Value {
    json!({
        "model": model,
        "input": [
            {
                "role": "developer",
                "content": [
                    {
                        "type": "input_text",
                        "text": "You are a secure coding assistant for Aegis WebShield AI. Return only practical, non-destructive remediation guidance."
                    }
                ]
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": prompt
                    }
                ]
            }
        ],
        "store": false,
        "reasoning": {
            "effort": "low"
        },
        "text": {
            "verbosity": "low",
            "format": {
                "type": "json_schema",
                "name": "aegis_ai_fix_guide",
                "strict": true,
                "schema": {
                    "type": "object",
                    "properties": {
                        "summary": {
                            "type": "string"
                        },
                        "safe_fix_steps": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "verification_steps": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "cautions": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    },
                    "required": ["summary", "safe_fix_steps", "verification_steps", "cautions"],
                    "additionalProperties": false
                }
            }
        }
    })
}

pub fn parse_openai_fix_guide(value: &Value, finding_id: &str) -> Result<AiFixGuide, AiGuideError> {
    let output_text = parse_openai_output_text(value)?;
    let body: AiFixGuideBody = serde_json::from_str(&output_text).map_err(|error| {
        AiGuideError::ProviderFailed(format!("invalid structured guide JSON: {}", error))
    })?;
    validate_guide_body(&body)?;
    Ok(AiFixGuide {
        finding_id: finding_id.to_string(),
        summary: body.summary,
        safe_fix_steps: body.safe_fix_steps,
        verification_steps: body.verification_steps,
        cautions: body.cautions,
    })
}

pub fn parse_openai_output_text(value: &Value) -> Result<String, AiGuideError> {
    if let Some(output_text) = value.get("output_text").and_then(Value::as_str) {
        if !output_text.trim().is_empty() {
            return Ok(output_text.trim().to_string());
        }
    }

    let Some(output) = value.get("output").and_then(Value::as_array) else {
        return Err(AiGuideError::ProviderFailed(
            "missing output text".to_string(),
        ));
    };
    let mut text = String::new();
    for item in output {
        if let Some(content) = item.get("content").and_then(Value::as_array) {
            for content_item in content {
                if let Some(part) = content_item.get("text").and_then(Value::as_str) {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(part);
                }
            }
        }
    }
    if text.trim().is_empty() {
        Err(AiGuideError::ProviderFailed(
            "missing output text".to_string(),
        ))
    } else {
        Ok(text.trim().to_string())
    }
}

fn validate_guide_body(body: &AiFixGuideBody) -> Result<(), AiGuideError> {
    if body.summary.trim().is_empty()
        || body.summary.len() > MAX_FIELD_LEN
        || body.safe_fix_steps.is_empty()
        || body.verification_steps.is_empty()
        || body.cautions.is_empty()
    {
        return Err(AiGuideError::ProviderFailed(
            "structured guide is incomplete".to_string(),
        ));
    }
    for value in body
        .safe_fix_steps
        .iter()
        .chain(body.verification_steps.iter())
        .chain(body.cautions.iter())
    {
        if value.trim().is_empty() || value.len() > MAX_FIELD_LEN || value.contains('\0') {
            return Err(AiGuideError::ProviderFailed(
                "structured guide contains invalid text".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn redact_secrets(value: &str) -> String {
    value
        .split_whitespace()
        .map(|part| {
            if looks_like_secret(part) {
                "[REDACTED]".to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_request(request: &AiFixGuideRequest) -> Result<(), AiGuideError> {
    for value in [
        &request.finding_id,
        &request.title,
        &request.severity,
        &request.endpoint,
        &request.evidence,
        &request.remediation_hint,
    ] {
        if value.trim().is_empty() || value.len() > MAX_FIELD_LEN || value.contains('\0') {
            return Err(AiGuideError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_api_key(value: &str) -> Result<(), AiGuideError> {
    let value = value.trim();
    if value.len() < 20 || value.contains('\0') {
        return Err(AiGuideError::MissingApiKey);
    }
    Ok(())
}

fn looks_like_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("sk-")
        || lower.contains("api_key=")
        || lower.contains("apikey=")
        || lower.contains("access_token=")
        || lower.contains("refresh_token=")
        || lower.contains("token=")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.contains("secret_key=")
        || lower.contains("private_key=")
        || lower.contains("authorization:")
        || lower == "bearer"
        || lower.contains("bearer ")
        || lower.contains("set-cookie:")
        || lower.contains("cookie:")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AiFixGuideRequest {
        AiFixGuideRequest {
            finding_id: "finding-1".to_string(),
            title: "Missing Content-Security-Policy header".to_string(),
            severity: "medium".to_string(),
            endpoint: "https://example.com".to_string(),
            evidence: "{\"header\":\"missing\"}".to_string(),
            remediation_hint: "Add a restrictive CSP header".to_string(),
        }
    }

    #[test]
    fn builds_redacted_prompt() {
        let mut request = request();
        request.evidence =
            "token=abc123 password=hunter2 Authorization: Bearer sk-secret should not leak"
                .to_string();

        let prompt = build_fix_guide_prompt(&request).expect("prompt");

        assert!(prompt.contains("[REDACTED]"));
        assert!(!prompt.contains("abc123"));
        assert!(!prompt.contains("hunter2"));
        assert!(!prompt.contains("sk-secret"));
    }

    #[test]
    fn deterministic_client_generates_safe_guide() {
        let guide = DeterministicFixGuideClient
            .generate_fix_guide(&request())
            .expect("guide");

        assert_eq!(guide.finding_id, "finding-1");
        assert!(!guide.safe_fix_steps.is_empty());
        assert!(!guide.verification_steps.is_empty());
        assert!(!guide.cautions.is_empty());
    }

    #[test]
    fn rejects_empty_input() {
        let mut request = request();
        request.title = " ".to_string();

        assert_eq!(
            build_fix_guide_prompt(&request),
            Err(AiGuideError::InvalidInput)
        );
    }

    #[test]
    fn builds_openai_responses_payload() {
        let payload = build_openai_response_payload("gpt-5.5", "Fix this finding");

        assert_eq!(payload["model"], "gpt-5.5");
        assert_eq!(payload["store"], false);
        assert_eq!(payload["text"]["verbosity"], "low");
        assert_eq!(payload["text"]["format"]["name"], "aegis_ai_fix_guide");
        assert_eq!(
            payload["text"]["format"]["schema"]["required"],
            json!([
                "summary",
                "safe_fix_steps",
                "verification_steps",
                "cautions"
            ])
        );
    }

    #[test]
    fn parses_openai_output_text_field() {
        let value = json!({ "output_text": "Use a CSP header." });

        assert_eq!(
            parse_openai_output_text(&value),
            Ok("Use a CSP header.".to_string())
        );
    }

    #[test]
    fn parses_openai_output_content_items() {
        let value = json!({
            "output": [
                {
                    "content": [
                        { "type": "output_text", "text": "Step 1" },
                        { "type": "output_text", "text": "Step 2" }
                    ]
                }
            ]
        });

        assert_eq!(
            parse_openai_output_text(&value),
            Ok("Step 1\nStep 2".to_string())
        );
    }

    #[test]
    fn parses_structured_openai_fix_guide() {
        let value = json!({
            "output_text": json!({
                "summary": "Add a Content-Security-Policy header.",
                "safe_fix_steps": ["Set a restrictive default-src policy."],
                "verification_steps": ["Re-run the approved passive scan."],
                "cautions": ["Roll out in staging first."]
            }).to_string()
        });

        let guide = parse_openai_fix_guide(&value, "finding-1").expect("guide");

        assert_eq!(guide.finding_id, "finding-1");
        assert_eq!(guide.summary, "Add a Content-Security-Policy header.");
        assert_eq!(guide.safe_fix_steps.len(), 1);
        assert_eq!(guide.verification_steps.len(), 1);
        assert_eq!(guide.cautions.len(), 1);
    }

    #[test]
    fn rejects_incomplete_structured_openai_fix_guide() {
        let value = json!({
            "output_text": json!({
                "summary": "Missing steps.",
                "safe_fix_steps": [],
                "verification_steps": ["Re-run scan."],
                "cautions": ["Review first."]
            }).to_string()
        });

        assert_eq!(
            parse_openai_fix_guide(&value, "finding-1"),
            Err(AiGuideError::ProviderFailed(
                "structured guide is incomplete".to_string()
            ))
        );
    }
}
