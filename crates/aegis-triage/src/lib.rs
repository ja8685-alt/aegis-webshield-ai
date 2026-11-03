use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleTriage {
    pub confidence: &'static str,
    pub cwe: Option<&'static str>,
    pub owasp_category: Option<&'static str>,
}

pub fn triage_rule(rule_id: &str) -> RuleTriage {
    match rule_id {
        "passive.missing_csp"
        | "aegis.config.header.csp"
        | "passive.csp_allows_unsafe_inline"
        | "passive.csp_inline_without_nonce_or_hash"
        | "passive.csp_allows_unsafe_eval"
        | "passive.csp_wildcard_source"
        | "passive.csp_allows_insecure_http"
        | "passive.missing_clickjacking_protection"
        | "aegis.config.header.frame-protection"
        | "passive.missing_x_content_type_options"
        | "aegis.config.header.nosniff"
        | "passive.missing_hsts"
        | "aegis.config.header.hsts"
        | "passive.missing_referrer_policy"
        | "passive.missing_permissions_policy"
        | "passive.missing_cross_origin_opener_policy"
        | "passive.missing_cross_origin_resource_policy"
        | "passive.missing_x_permitted_cross_domain_policies" => RuleTriage {
            confidence: "high",
            cwe: Some("CWE-693"),
            owasp_category: Some("A05 Security Misconfiguration"),
        },
        "passive.cookie_missing_secure"
        | "aegis.config.cookie.secure"
        | "passive.cookie_missing_http_only"
        | "aegis.config.cookie.httponly"
        | "passive.cookie_missing_same_site"
        | "passive.cookie_same_site_none_without_secure"
        | "aegis.config.cookie.samesite"
        | "aegis.config.cookie.host-prefix"
        | "aegis.config.cookie.secure-prefix" => RuleTriage {
            confidence: "high",
            cwe: Some("CWE-614"),
            owasp_category: Some("A05 Security Misconfiguration"),
        },
        "passive.server_header_disclosure" | "aegis.exposure.version-banner" => RuleTriage {
            confidence: "medium",
            cwe: Some("CWE-200"),
            owasp_category: Some("A05 Security Misconfiguration"),
        },
        "passive.cors_wildcard_with_credentials"
        | "passive.sensitive_response_cacheable"
        | "passive.mixed_content_reference"
        | "passive.missing_https_redirect"
        | "passive.source_map_exposed" => RuleTriage {
            confidence: "medium",
            cwe: Some("CWE-693"),
            owasp_category: Some("A05 Security Misconfiguration"),
        },
        "passive.sensitive_token_pattern"
        | "aegis.exposure.secret-pattern"
        | "aegis.exposure.secret-assignment" => RuleTriage {
            confidence: "high",
            cwe: Some("CWE-200"),
            owasp_category: Some("A02 Cryptographic Failures"),
        },
        "active.reflected_xss_signal" | "aegis.candidate.reflected-xss" => RuleTriage {
            confidence: "medium",
            cwe: Some("CWE-79"),
            owasp_category: Some("A03 Injection"),
        },
        "active.open_redirect_signal" => RuleTriage {
            confidence: "medium",
            cwe: Some("CWE-601"),
            owasp_category: Some("A01 Broken Access Control"),
        },
        "active.error_based_sqli_signal" | "aegis.candidate.sql-injection" => RuleTriage {
            confidence: "medium",
            cwe: Some("CWE-89"),
            owasp_category: Some("A03 Injection"),
        },
        "active.path_traversal_signal" => RuleTriage {
            confidence: "high",
            cwe: Some("CWE-22"),
            owasp_category: Some("A01 Broken Access Control"),
        },
        "surface.exposed_git_metadata"
        | "surface.exposed_env_file"
        | "surface.exposed_backup_or_dump_file" => RuleTriage {
            confidence: "high",
            cwe: Some("CWE-538"),
            owasp_category: Some("A01 Broken Access Control"),
        },
        "surface.exposed_debug_endpoint" | "surface.admin_console_reachable" => RuleTriage {
            confidence: "medium",
            cwe: Some("CWE-284"),
            owasp_category: Some("A01 Broken Access Control"),
        },
        "surface.directory_listing_enabled" => RuleTriage {
            confidence: "high",
            cwe: Some("CWE-548"),
            owasp_category: Some("A05 Security Misconfiguration"),
        },
        "surface.stack_trace_disclosure" | "aegis.exposure.stack-trace" => RuleTriage {
            confidence: "high",
            cwe: Some("CWE-209"),
            owasp_category: Some("A05 Security Misconfiguration"),
        },
        _ => RuleTriage {
            confidence: "medium",
            cwe: None,
            owasp_category: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_security_header_rules() {
        let triage = triage_rule("passive.missing_csp");

        assert_eq!(triage.confidence, "high");
        assert_eq!(triage.cwe, Some("CWE-693"));
        assert_eq!(triage.owasp_category, Some("A05 Security Misconfiguration"));
    }

    #[test]
    fn maps_cookie_rules() {
        let triage = triage_rule("passive.cookie_missing_secure");

        assert_eq!(triage.confidence, "high");
        assert_eq!(triage.cwe, Some("CWE-614"));
    }

    #[test]
    fn maps_surface_exposure_rules() {
        let triage = triage_rule("surface.exposed_env_file");

        assert_eq!(triage.confidence, "high");
        assert_eq!(triage.cwe, Some("CWE-538"));
        assert_eq!(triage.owasp_category, Some("A01 Broken Access Control"));
    }

    #[test]
    fn maps_extended_passive_rules() {
        let cors = triage_rule("passive.cors_wildcard_with_credentials");
        let token = triage_rule("passive.sensitive_token_pattern");

        assert_eq!(cors.confidence, "medium");
        assert_eq!(cors.cwe, Some("CWE-693"));
        assert_eq!(token.confidence, "high");
        assert_eq!(token.cwe, Some("CWE-200"));
    }

    #[test]
    fn maps_safe_active_rules() {
        let reflected = triage_rule("active.reflected_xss_signal");
        let redirect = triage_rule("active.open_redirect_signal");
        let sqli = triage_rule("active.error_based_sqli_signal");
        let path_traversal = triage_rule("active.path_traversal_signal");

        assert_eq!(reflected.confidence, "medium");
        assert_eq!(reflected.cwe, Some("CWE-79"));
        assert_eq!(redirect.cwe, Some("CWE-601"));
        assert_eq!(sqli.cwe, Some("CWE-89"));
        assert_eq!(sqli.owasp_category, Some("A03 Injection"));
        assert_eq!(path_traversal.confidence, "high");
        assert_eq!(path_traversal.cwe, Some("CWE-22"));
    }

    #[test]
    fn falls_back_for_unknown_rules() {
        let triage = triage_rule("custom.unknown");

        assert_eq!(triage.confidence, "medium");
        assert_eq!(triage.cwe, None);
        assert_eq!(triage.owasp_category, None);
    }
}
