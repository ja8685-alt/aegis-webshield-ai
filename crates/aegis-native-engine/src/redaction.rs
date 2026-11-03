use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde::{Deserialize, Deserializer, Serialize};

use crate::ContractError;

const REDACTED: &str = "[REDACTED]";

/// Text that is redacted and byte-bounded before it crosses a service boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedText {
    value: String,
    truncated: bool,
}

impl<'de> Deserialize<'de> for RedactedText {
    fn deserialize<DeserializerType>(
        deserializer: DeserializerType,
    ) -> Result<Self, DeserializerType::Error>
    where
        DeserializerType: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedRedactedText {
            value: String,
            truncated: bool,
        }

        let serialized = SerializedRedactedText::deserialize(deserializer)?;
        let mut redacted =
            RedactedText::new(&serialized.value, 16_384).map_err(serde::de::Error::custom)?;
        redacted.truncated |= serialized.truncated;
        Ok(redacted)
    }
}

impl RedactedText {
    /// Redacts common credential forms and truncates to a UTF-8 boundary.
    pub fn new(value: &str, max_bytes: usize) -> Result<Self, ContractError> {
        if max_bytes == 0 {
            return Err(ContractError::new("max_bytes", "must be greater than zero"));
        }
        let redacted = redact_sensitive_text(value);
        let truncated = redacted.len() > max_bytes;
        let value = truncate_utf8(&redacted, max_bytes).to_string();
        Ok(Self { value, truncated })
    }

    /// Returns already-redacted text.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Whether the redacted text exceeded the configured byte limit.
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Redacts credential assignments, authorization values, cookies, and JWT-like values.
pub fn redact_sensitive_text(value: &str) -> String {
    let assignments = sensitive_assignment_regex();
    let redacted = assignments.replace_all(value, |captures: &Captures<'_>| {
        format!("{}{}", &captures[1], REDACTED)
    });
    jwt_regex().replace_all(&redacted, REDACTED).into_owned()
}

fn sensitive_assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)((?:"?(?:authorization|proxy-authorization|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret|cookie)"?)\s*[:=]\s*"?(?:bearer\s+)?)(?:\[REDACTED\]|[^"\s,;&}\]]+)"#,
        )
        .expect("sensitive assignment regex must compile")
    })
}

fn jwt_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
            .expect("JWT regex must compile")
    })
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    &value[..boundary]
}

#[cfg(test)]
mod tests {
    use super::{redact_sensitive_text, RedactedText};

    #[test]
    fn redacts_assignments_and_jwt_without_removing_safe_context() {
        let input = "Authorization: Bearer top-secret access_token=abc123 endpoint=/orders eyJabcdefgh.a23456789.b23456789";
        let redacted = redact_sensitive_text(input);
        assert!(redacted.contains("endpoint=/orders"));
        assert!(!redacted.contains("top-secret"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("eyJabcdefgh"));
    }

    #[test]
    fn truncates_on_utf8_boundary_after_redaction() {
        let text = RedactedText::new("가나다라마바사", 8).unwrap();
        assert_eq!(text.as_str(), "가나");
        assert!(text.truncated());
    }

    #[test]
    fn deserialization_cannot_bypass_redaction() {
        let serialized = r#"{"value":"access_token=raw-secret","truncated":false}"#;
        let text: RedactedText = serde_json::from_str(serialized).unwrap();
        assert!(!text.as_str().contains("raw-secret"));
        assert!(text.as_str().contains("[REDACTED]"));
    }

    #[test]
    fn redaction_is_idempotent_for_serialized_values() {
        let once = redact_sensitive_text("access_token=raw-secret");
        let twice = redact_sensitive_text(&once);
        assert_eq!(twice, once);
    }
}
