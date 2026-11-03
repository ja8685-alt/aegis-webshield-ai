use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};

use aegis_native_engine::{FindingIdentity, HttpMethod, ParameterLocation};

const HARD_MAX_SAMPLES_PER_ROLE: usize = 5;
const HARD_MAX_BODY_VIEW_BYTES: usize = 65_536;
const HARD_MAX_OCCURRENCES_PER_BODY: usize = 16;
const MARKER_PREFIX: &str = "aegisxss_";

pub struct XssProbeContract<'a> {
    pub target_id: &'a str,
    pub endpoint: &'a str,
    pub method: HttpMethod,
    pub parameter_location: ParameterLocation,
    pub parameter_name: &'a str,
    pub probe_marker: &'a str,
    pub control_marker: &'a str,
    pub explicitly_approved: bool,
}

impl Debug for XssProbeContract<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XssProbeContract")
            .field("method", &self.method)
            .field("parameter_location", &self.parameter_location)
            .field("parameter_name_bytes", &self.parameter_name.len())
            .field("probe_marker_bytes", &self.probe_marker.len())
            .field("control_marker_bytes", &self.control_marker.len())
            .field("explicitly_approved", &self.explicitly_approved)
            .finish()
    }
}

pub struct XssResponseSample<'a> {
    pub content_type: &'a str,
    pub body_view: &'a [u8],
    pub body_view_truncated: bool,
    pub evidence_ref: &'a str,
}

impl Debug for XssResponseSample<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XssResponseSample")
            .field("content_type_bytes", &self.content_type.len())
            .field("body_view_bytes", &self.body_view.len())
            .field("body_view_truncated", &self.body_view_truncated)
            .finish()
    }
}

pub struct XssReflectionInput<'a> {
    pub contract: XssProbeContract<'a>,
    pub baseline: &'a [XssResponseSample<'a>],
    pub probe: &'a [XssResponseSample<'a>],
    pub control: &'a [XssResponseSample<'a>],
}

impl Debug for XssReflectionInput<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XssReflectionInput")
            .field("contract", &self.contract)
            .field("baseline_samples", &self.baseline.len())
            .field("probe_samples", &self.probe.len())
            .field("control_samples", &self.control.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XssReflectionLimits {
    pub max_samples_per_role: usize,
    pub max_body_view_bytes: usize,
    pub max_occurrences_per_body: usize,
}

impl Default for XssReflectionLimits {
    fn default() -> Self {
        Self {
            max_samples_per_role: HARD_MAX_SAMPLES_PER_ROLE,
            max_body_view_bytes: HARD_MAX_BODY_VIEW_BYTES,
            max_occurrences_per_body: HARD_MAX_OCCURRENCES_PER_BODY,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XssReflectionRuntimeError {
    InvalidLimits,
    InvalidContract,
    UnapprovedProbe,
    InvalidInput,
    OccurrenceLimitExceeded,
}

impl Display for XssReflectionRuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "XSS reflection limits are invalid",
            Self::InvalidContract => "XSS reflection contract is invalid",
            Self::UnapprovedProbe => "XSS reflection probe was not explicitly approved",
            Self::InvalidInput => "XSS reflection response input is invalid",
            Self::OccurrenceLimitExceeded => "XSS marker occurrence limit was exceeded",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for XssReflectionRuntimeError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReflectionContext {
    HtmlText,
    QuotedAttribute,
    UnquotedAttribute,
    UrlAttribute,
    ScriptData,
    StyleData,
    TagStructure,
    HtmlComment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XssReflectionDecision {
    Candidate,
    NotReflected,
    Abstain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XssCandidate {
    pub candidate_id: String,
    pub context: ReflectionContext,
    pub requires_execution_verification: bool,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XssReflectionAssessment {
    pub decision: XssReflectionDecision,
    pub reflected_context: Option<ReflectionContext>,
    pub candidate: Option<XssCandidate>,
    pub probe_reflection_count: usize,
    pub control_reflection_count: usize,
}

pub fn assess_xss_reflection(
    input: &XssReflectionInput<'_>,
    limits: XssReflectionLimits,
) -> Result<XssReflectionAssessment, XssReflectionRuntimeError> {
    validate_limits(limits)?;
    let identity = validate_contract(&input.contract)?;
    if !input.contract.explicitly_approved {
        return Err(XssReflectionRuntimeError::UnapprovedProbe);
    }
    validate_samples(input, limits)?;
    if input.baseline.iter().any(|sample| {
        contains(sample.body_view, input.contract.probe_marker.as_bytes())
            || contains(sample.body_view, input.contract.control_marker.as_bytes())
    }) {
        return Ok(abstain());
    }

    let probe = role_contexts(input.probe, input.contract.probe_marker, limits)?;
    let control = role_contexts(input.control, input.contract.control_marker, limits)?;
    let probe_count = probe.iter().map(Vec::len).sum();
    let control_count = control.iter().map(Vec::len).sum();
    if probe_count == 0 && control_count == 0 {
        return Ok(XssReflectionAssessment {
            decision: XssReflectionDecision::NotReflected,
            reflected_context: None,
            candidate: None,
            probe_reflection_count: 0,
            control_reflection_count: 0,
        });
    }
    let Some(probe_context) = consistent_role_context(&probe) else {
        return Ok(abstain_with_counts(probe_count, control_count));
    };
    let Some(control_context) = consistent_role_context(&control) else {
        return Ok(abstain_with_counts(probe_count, control_count));
    };
    if probe_context != control_context || probe_context == ReflectionContext::HtmlComment {
        return Ok(abstain_with_counts(probe_count, control_count));
    }
    let candidate_id = format!("xss-candidate-{}", &identity.fingerprint()[..24]);
    let evidence_refs = input
        .probe
        .iter()
        .chain(input.control)
        .map(|sample| sample.evidence_ref)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_string)
        .collect();
    Ok(XssReflectionAssessment {
        decision: XssReflectionDecision::Candidate,
        reflected_context: Some(probe_context),
        candidate: Some(XssCandidate {
            candidate_id,
            context: probe_context,
            requires_execution_verification: true,
            evidence_refs,
        }),
        probe_reflection_count: probe_count,
        control_reflection_count: control_count,
    })
}

fn validate_limits(limits: XssReflectionLimits) -> Result<(), XssReflectionRuntimeError> {
    if limits.max_samples_per_role < 2
        || limits.max_samples_per_role > HARD_MAX_SAMPLES_PER_ROLE
        || limits.max_body_view_bytes == 0
        || limits.max_body_view_bytes > HARD_MAX_BODY_VIEW_BYTES
        || limits.max_occurrences_per_body == 0
        || limits.max_occurrences_per_body > HARD_MAX_OCCURRENCES_PER_BODY
    {
        return Err(XssReflectionRuntimeError::InvalidLimits);
    }
    Ok(())
}

fn validate_contract(
    contract: &XssProbeContract<'_>,
) -> Result<FindingIdentity, XssReflectionRuntimeError> {
    if !matches!(contract.method, HttpMethod::Get | HttpMethod::Post)
        || !matches!(
            contract.parameter_location,
            ParameterLocation::Query | ParameterLocation::Form | ParameterLocation::JsonBody
        )
        || !valid_marker(contract.probe_marker)
        || !valid_marker(contract.control_marker)
        || contract.probe_marker == contract.control_marker
    {
        return Err(XssReflectionRuntimeError::InvalidContract);
    }
    FindingIdentity::new(
        contract.target_id,
        contract.method,
        contract.endpoint,
        "CWE-79",
        contract.parameter_location,
        Some(contract.parameter_name.to_string()),
    )
    .map_err(|_| XssReflectionRuntimeError::InvalidContract)
}

fn valid_marker(marker: &str) -> bool {
    marker.len() == MARKER_PREFIX.len() + 16
        && marker.starts_with(MARKER_PREFIX)
        && marker[MARKER_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn validate_samples(
    input: &XssReflectionInput<'_>,
    limits: XssReflectionLimits,
) -> Result<(), XssReflectionRuntimeError> {
    for samples in [input.baseline, input.probe, input.control] {
        if samples.len() < 2 || samples.len() > limits.max_samples_per_role {
            return Err(XssReflectionRuntimeError::InvalidInput);
        }
        for sample in samples {
            if sample.body_view_truncated
                || sample.body_view.len() > limits.max_body_view_bytes
                || !is_html(sample.content_type)
                || std::str::from_utf8(sample.body_view).is_err()
                || sample.evidence_ref.is_empty()
                || sample.evidence_ref.len() > 64
                || !sample.evidence_ref.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
            {
                return Err(XssReflectionRuntimeError::InvalidInput);
            }
        }
    }
    Ok(())
}

fn is_html(content_type: &str) -> bool {
    matches!(
        content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "text/html" | "application/xhtml+xml"
    )
}

fn role_contexts(
    samples: &[XssResponseSample<'_>],
    marker: &str,
    limits: XssReflectionLimits,
) -> Result<Vec<Vec<ReflectionContext>>, XssReflectionRuntimeError> {
    samples
        .iter()
        .map(|sample| classify_occurrences(sample.body_view, marker.as_bytes(), limits))
        .collect()
}

fn classify_occurrences(
    body: &[u8],
    marker: &[u8],
    limits: XssReflectionLimits,
) -> Result<Vec<ReflectionContext>, XssReflectionRuntimeError> {
    let mut contexts = Vec::new();
    let mut offset = 0;
    while offset + marker.len() <= body.len() {
        let Some(relative) = body[offset..]
            .windows(marker.len())
            .position(|window| window == marker)
        else {
            break;
        };
        let index = offset + relative;
        if contexts.len() >= limits.max_occurrences_per_body {
            return Err(XssReflectionRuntimeError::OccurrenceLimitExceeded);
        }
        contexts.push(classify_context(body, index));
        offset = index + marker.len();
    }
    Ok(contexts)
}

fn classify_context(body: &[u8], marker_index: usize) -> ReflectionContext {
    let prefix = &body[..marker_index];
    if open_region(prefix, b"<!--", b"-->") {
        return ReflectionContext::HtmlComment;
    }
    let last_open = prefix.iter().rposition(|byte| *byte == b'<');
    let last_close = prefix.iter().rposition(|byte| *byte == b'>');
    if last_open.is_some() && last_open > last_close {
        return classify_tag_context(&prefix[last_open.unwrap_or(0) + 1..]);
    }
    if open_region_ci(prefix, b"<script", b"</script") {
        return ReflectionContext::ScriptData;
    }
    if open_region_ci(prefix, b"<style", b"</style") {
        return ReflectionContext::StyleData;
    }
    ReflectionContext::HtmlText
}

fn classify_tag_context(tag_prefix: &[u8]) -> ReflectionContext {
    let single_quotes = tag_prefix.iter().filter(|byte| **byte == b'\'').count();
    let double_quotes = tag_prefix.iter().filter(|byte| **byte == b'"').count();
    let quoted = single_quotes % 2 == 1 || double_quotes % 2 == 1;
    let Some(equal_index) = tag_prefix.iter().rposition(|byte| *byte == b'=') else {
        return ReflectionContext::TagStructure;
    };
    let attribute = tag_prefix[..equal_index]
        .rsplit(|byte| byte.is_ascii_whitespace())
        .next()
        .unwrap_or(&[]);
    if matches_ci(
        attribute,
        &[b"href", b"src", b"action", b"formaction", b"xlink:href"],
    ) {
        ReflectionContext::UrlAttribute
    } else if quoted {
        ReflectionContext::QuotedAttribute
    } else {
        ReflectionContext::UnquotedAttribute
    }
}

fn matches_ci(value: &[u8], candidates: &[&[u8]]) -> bool {
    candidates.iter().any(|candidate| {
        value.len() == candidate.len()
            && value
                .iter()
                .zip(*candidate)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn open_region(prefix: &[u8], opening: &[u8], closing: &[u8]) -> bool {
    last_position(prefix, opening) > last_position(prefix, closing)
}

fn open_region_ci(prefix: &[u8], opening: &[u8], closing: &[u8]) -> bool {
    last_position_ci(prefix, opening) > last_position_ci(prefix, closing)
}

fn last_position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn last_position_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn consistent_role_context(contexts: &[Vec<ReflectionContext>]) -> Option<ReflectionContext> {
    let first = *contexts.first()?.first()?;
    contexts
        .iter()
        .all(|sample| !sample.is_empty() && sample.iter().all(|context| *context == first))
        .then_some(first)
}

fn abstain() -> XssReflectionAssessment {
    abstain_with_counts(0, 0)
}

fn abstain_with_counts(probe_count: usize, control_count: usize) -> XssReflectionAssessment {
    XssReflectionAssessment {
        decision: XssReflectionDecision::Abstain,
        reflected_context: None,
        candidate: None,
        probe_reflection_count: probe_count,
        control_reflection_count: control_count,
    }
}

pub(crate) fn benchmark_outcomes() -> Result<(bool, bool), XssReflectionRuntimeError> {
    const PROBE: &str = "aegisxss_0123456789abcdef";
    const CONTROL: &str = "aegisxss_fedcba9876543210";
    let samples = |body| {
        vec![
            XssResponseSample {
                content_type: "text/html; charset=utf-8",
                body_view: body,
                body_view_truncated: false,
                evidence_ref: "benchmark-1",
            },
            XssResponseSample {
                content_type: "text/html",
                body_view: body,
                body_view_truncated: false,
                evidence_ref: "benchmark-2",
            },
        ]
    };
    let baseline = samples(br#"<input value="normal">"#);
    let probe_body = format!(r#"<input value="{PROBE}">"#);
    let control_body = format!(r#"<input value="{CONTROL}">"#);
    let probe = samples(probe_body.as_bytes());
    let control = samples(control_body.as_bytes());
    let contract = || XssProbeContract {
        target_id: "benchmark-target",
        endpoint: "https://benchmark.invalid/search",
        method: HttpMethod::Get,
        parameter_location: ParameterLocation::Query,
        parameter_name: "query",
        probe_marker: PROBE,
        control_marker: CONTROL,
        explicitly_approved: true,
    };
    let positive = assess_xss_reflection(
        &XssReflectionInput {
            contract: contract(),
            baseline: &baseline,
            probe: &probe,
            control: &control,
        },
        XssReflectionLimits::default(),
    )?;
    let clean_probe = samples(b"<p>normal</p>");
    let clean_control = samples(b"<p>normal</p>");
    let negative = assess_xss_reflection(
        &XssReflectionInput {
            contract: contract(),
            baseline: &baseline,
            probe: &clean_probe,
            control: &clean_control,
        },
        XssReflectionLimits::default(),
    )?;
    Ok((
        positive.decision == XssReflectionDecision::Candidate && positive.candidate.is_some(),
        negative.decision == XssReflectionDecision::Candidate || negative.candidate.is_some(),
    ))
}

#[cfg(test)]
mod tests {
    use aegis_native_engine::{HttpMethod, ParameterLocation};

    use super::{
        assess_xss_reflection, ReflectionContext, XssProbeContract, XssReflectionDecision,
        XssReflectionInput, XssReflectionLimits, XssReflectionRuntimeError, XssResponseSample,
    };

    const PROBE: &str = "aegisxss_0123456789abcdef";
    const CONTROL: &str = "aegisxss_fedcba9876543210";

    fn samples<'a>(body: &'a [u8]) -> Vec<XssResponseSample<'a>> {
        vec![
            XssResponseSample {
                content_type: "text/html; charset=utf-8",
                body_view: body,
                body_view_truncated: false,
                evidence_ref: "evidence-1",
            },
            XssResponseSample {
                content_type: "text/html",
                body_view: body,
                body_view_truncated: false,
                evidence_ref: "evidence-2",
            },
        ]
    }

    fn input<'a>(
        baseline: &'a [XssResponseSample<'a>],
        probe: &'a [XssResponseSample<'a>],
        control: &'a [XssResponseSample<'a>],
    ) -> XssReflectionInput<'a> {
        XssReflectionInput {
            contract: XssProbeContract {
                target_id: "target-1",
                endpoint: "https://example.com/search",
                method: HttpMethod::Get,
                parameter_location: ParameterLocation::Query,
                parameter_name: "query",
                probe_marker: PROBE,
                control_marker: CONTROL,
                explicitly_approved: true,
            },
            baseline,
            probe,
            control,
        }
    }

    #[test]
    fn stable_attribute_reflection_is_candidate_not_confirmed_finding() {
        let baseline = samples(br#"<input value="normal">"#);
        let probe_body = format!(r#"<input value="{PROBE}">"#);
        let control_body = format!(r#"<input value="{CONTROL}">"#);
        let probe = samples(probe_body.as_bytes());
        let control = samples(control_body.as_bytes());
        let assessment = assess_xss_reflection(
            &input(&baseline, &probe, &control),
            XssReflectionLimits::default(),
        )
        .unwrap();
        assert_eq!(assessment.decision, XssReflectionDecision::Candidate);
        assert_eq!(
            assessment.reflected_context,
            Some(ReflectionContext::QuotedAttribute)
        );
        assert!(
            assessment
                .candidate
                .as_ref()
                .unwrap()
                .requires_execution_verification
        );
    }

    #[test]
    fn script_url_and_text_contexts_are_classified() {
        for (probe_body, control_body, expected) in [
            (
                format!("<script>const value='{PROBE}'</script>"),
                format!("<script>const value='{CONTROL}'</script>"),
                ReflectionContext::ScriptData,
            ),
            (
                format!(r#"<a href="{PROBE}">link</a>"#),
                format!(r#"<a href="{CONTROL}">link</a>"#),
                ReflectionContext::UrlAttribute,
            ),
            (
                format!("<p>{PROBE}</p>"),
                format!("<p>{CONTROL}</p>"),
                ReflectionContext::HtmlText,
            ),
            (
                format!("<style>.item {{ color: {PROBE}; }}</style>"),
                format!("<style>.item {{ color: {CONTROL}; }}</style>"),
                ReflectionContext::StyleData,
            ),
            (
                format!("<div data-value={PROBE}>item</div>"),
                format!("<div data-value={CONTROL}>item</div>"),
                ReflectionContext::UnquotedAttribute,
            ),
            (
                format!("<div {PROBE}>item</div>"),
                format!("<div {CONTROL}>item</div>"),
                ReflectionContext::TagStructure,
            ),
        ] {
            let baseline = samples(b"<p>normal</p>");
            let probe = samples(probe_body.as_bytes());
            let control = samples(control_body.as_bytes());
            let assessment = assess_xss_reflection(
                &input(&baseline, &probe, &control),
                XssReflectionLimits::default(),
            )
            .unwrap();
            assert_eq!(assessment.reflected_context, Some(expected));
        }
    }

    #[test]
    fn comments_collisions_and_unstable_control_abstain() {
        let baseline = samples(b"<p>normal</p>");
        let probe_body = format!("<!-- {PROBE} -->");
        let control_body = format!("<!-- {CONTROL} -->");
        let probe = samples(probe_body.as_bytes());
        let control = samples(control_body.as_bytes());
        assert_eq!(
            assess_xss_reflection(
                &input(&baseline, &probe, &control),
                XssReflectionLimits::default(),
            )
            .unwrap()
            .decision,
            XssReflectionDecision::Abstain
        );

        let collision_body = format!("<p>{PROBE}</p>");
        let collision = samples(collision_body.as_bytes());
        assert_eq!(
            assess_xss_reflection(
                &input(&collision, &probe, &control),
                XssReflectionLimits::default(),
            )
            .unwrap()
            .decision,
            XssReflectionDecision::Abstain
        );
    }

    #[test]
    fn absent_marker_is_not_reflected_and_debug_is_redacted() {
        let baseline = samples(b"<p>normal</p>");
        let probe = samples(b"<p>normal</p>");
        let control = samples(b"<p>normal</p>");
        let input = input(&baseline, &probe, &control);
        let assessment = assess_xss_reflection(&input, XssReflectionLimits::default()).unwrap();
        assert_eq!(assessment.decision, XssReflectionDecision::NotReflected);
        let debug = format!("{input:?}");
        assert!(!debug.contains("example.com"));
        assert!(!debug.contains(PROBE));
    }

    #[test]
    fn approval_marker_and_sample_limits_fail_closed() {
        let baseline = samples(b"<p>normal</p>");
        let probe = samples(b"<p>normal</p>");
        let control = samples(b"<p>normal</p>");
        let mut input = input(&baseline, &probe, &control);
        input.contract.explicitly_approved = false;
        assert_eq!(
            assess_xss_reflection(&input, XssReflectionLimits::default()),
            Err(XssReflectionRuntimeError::UnapprovedProbe)
        );
        input.contract.explicitly_approved = true;
        input.contract.probe_marker = "<script>alert(1)</script>";
        assert_eq!(
            assess_xss_reflection(&input, XssReflectionLimits::default()),
            Err(XssReflectionRuntimeError::InvalidContract)
        );
    }
}
