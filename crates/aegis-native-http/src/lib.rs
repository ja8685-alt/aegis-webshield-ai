//! Sandboxed async HTTP execution adapter for Aegis Native Security Engine.

mod credential;
mod runtime;

#[cfg(test)]
mod isolation_tests;

use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use aegis_native_engine::{
    ApprovedTarget, HeaderRecord, HttpMethod, NativeRequestRecord, NativeResponseRecord,
    PayloadSummary, MAX_RESPONSE_BYTES,
};
use async_trait::async_trait;
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CACHE_CONTROL};
use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use tokio::net::lookup_host;
use url::Url;
use zeroize::Zeroizing;

pub use credential::{CredentialKind, CredentialScope, EphemeralCredential};
pub use runtime::{
    bounded_work_queue, CancellationToken, ExecutionPermit, ExecutionRuntimeConfig,
    RequestActivity, RequestBudgetSnapshot, RuntimeControlError, TargetExecutionGate, WorkReceiver,
    WorkSender,
};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_REDIRECTS: usize = 5;
const USER_AGENT: &str = "AegisNativeSecurityEngine/0.1";

/// Safe runtime bounds for one HTTP execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpExecutionLimits {
    pub request_timeout: Duration,
    pub max_redirects: usize,
    pub max_response_bytes: u64,
}

impl Default for HttpExecutionLimits {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl HttpExecutionLimits {
    /// Rejects values that would weaken the D-146 hard upper bounds.
    pub fn validate(&self) -> Result<(), HttpExecutionError> {
        if self.request_timeout.is_zero() || self.request_timeout > DEFAULT_REQUEST_TIMEOUT {
            return Err(HttpExecutionError::InvalidLimits);
        }
        if self.max_redirects > DEFAULT_MAX_REDIRECTS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(HttpExecutionError::InvalidLimits);
        }
        Ok(())
    }
}

/// Sanitized executor errors that never include target URLs, headers, or response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpExecutionError {
    InvalidLimits,
    InvalidRequest,
    UnsupportedMethod,
    UnsupportedHeader,
    DnsResolutionFailed,
    ForbiddenDestination,
    ConnectionFailed,
    TlsOrProtocolFailed,
    RedirectMissingLocation,
    RedirectOutOfScope,
    RedirectLimitExceeded,
    ResponseTooLarge,
    ResponseRecordInvalid,
    CredentialInvalid,
    CredentialScopeMismatch,
    Cancelled,
}

impl Display for HttpExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidLimits => "HTTP execution limits are invalid",
            Self::InvalidRequest => "HTTP request record is invalid",
            Self::UnsupportedMethod => "HTTP method is not enabled by this executor",
            Self::UnsupportedHeader => "HTTP header is not enabled by this executor",
            Self::DnsResolutionFailed => "target DNS resolution failed",
            Self::ForbiddenDestination => "target resolved to a forbidden destination",
            Self::ConnectionFailed => "target connection failed",
            Self::TlsOrProtocolFailed => "target TLS or HTTP protocol failed",
            Self::RedirectMissingLocation => "redirect response omitted a valid location",
            Self::RedirectOutOfScope => "redirect left the approved target scope",
            Self::RedirectLimitExceeded => "redirect limit exceeded",
            Self::ResponseTooLarge => "response exceeded the configured byte limit",
            Self::ResponseRecordInvalid => "response could not be represented safely",
            Self::CredentialInvalid => "credential is invalid",
            Self::CredentialScopeMismatch => "credential is outside its approved target scope",
            Self::Cancelled => "HTTP execution cancelled",
        };
        formatter.write_str(message)
    }
}

impl Error for HttpExecutionError {}

/// DNS port that can be replaced by a deterministic test resolver.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, HttpExecutionError>;
}

/// System DNS resolver used by the scanner worker adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, HttpExecutionError> {
        let addresses = lookup_host((host, port))
            .await
            .map_err(|_| HttpExecutionError::DnsResolutionFailed)?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(HttpExecutionError::DnsResolutionFailed);
        }
        Ok(addresses)
    }
}

/// Destination classification port used at every connection and redirect.
pub trait AddressPolicy: Send + Sync {
    fn allows(&self, address: IpAddr) -> bool;
}

/// Security classification for resolved IPv4 and IPv6 destinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationClass {
    Public,
    Unspecified,
    Loopback,
    Private,
    Shared,
    LinkLocal,
    Documentation,
    Benchmark,
    Multicast,
    Translation,
    Reserved,
}

/// Public-network-only destination policy for SaaS execution.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublicAddressPolicy;

impl AddressPolicy for PublicAddressPolicy {
    fn allows(&self, address: IpAddr) -> bool {
        classify_destination(address) == DestinationClass::Public
    }
}

/// Classifies a destination without DNS or network side effects.
pub fn classify_destination(address: IpAddr) -> DestinationClass {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

/// Runtime response keeps bounded body bytes in worker memory and excludes them from Debug.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectionHeader {
    pub name: String,
    pub value: String,
}

/// Runtime response keeps bounded body bytes in worker memory and excludes them from Debug.
pub struct ExecutedResponse {
    pub record: NativeResponseRecord,
    pub remote_address: SocketAddr,
    detection_headers: Vec<DetectionHeader>,
    body: Zeroizing<Vec<u8>>,
}

impl ExecutedResponse {
    /// Bounded in-memory body for deterministic rule evaluation.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Sanitized response headers retained only for worker-local deterministic detection.
    pub fn detection_headers(&self) -> &[DetectionHeader] {
        &self.detection_headers
    }
}

impl Debug for ExecutedResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutedResponse")
            .field("record", &self.record)
            .field("remote_address", &self.remote_address)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

/// Async executor that pins each request to a validated DNS result.
pub struct NativeHttpExecutor<Resolver, PolicyType> {
    resolver: Resolver,
    address_policy: PolicyType,
    limits: HttpExecutionLimits,
}

impl<Resolver, PolicyType> NativeHttpExecutor<Resolver, PolicyType>
where
    Resolver: DnsResolver,
    PolicyType: AddressPolicy,
{
    /// Creates an executor without weakening global safety limits.
    pub fn new(
        resolver: Resolver,
        address_policy: PolicyType,
        limits: HttpExecutionLimits,
    ) -> Result<Self, HttpExecutionError> {
        limits.validate()?;
        Ok(Self {
            resolver,
            address_policy,
            limits,
        })
    }

    /// Executes one safe request and follows only manually revalidated redirects.
    pub async fn execute(
        &self,
        target: &ApprovedTarget,
        request: &NativeRequestRecord,
    ) -> Result<ExecutedResponse, HttpExecutionError> {
        self.execute_with_controls(target, request, None, None)
            .await
    }

    /// Executes one request while allowing a scan cancellation signal to abort network I/O.
    pub async fn execute_cancellable(
        &self,
        target: &ApprovedTarget,
        request: &NativeRequestRecord,
        cancellation: &CancellationToken,
    ) -> Result<ExecutedResponse, HttpExecutionError> {
        self.execute_with_controls(target, request, None, Some(cancellation))
            .await
    }

    /// Executes one request with an ephemeral worker-only credential.
    pub async fn execute_authenticated(
        &self,
        target: &ApprovedTarget,
        request: &NativeRequestRecord,
        credential: &EphemeralCredential,
    ) -> Result<ExecutedResponse, HttpExecutionError> {
        self.execute_with_controls(target, request, Some(credential), None)
            .await
    }

    /// Executes one authenticated request with cancellation-aware network waits.
    pub async fn execute_authenticated_cancellable(
        &self,
        target: &ApprovedTarget,
        request: &NativeRequestRecord,
        credential: &EphemeralCredential,
        cancellation: &CancellationToken,
    ) -> Result<ExecutedResponse, HttpExecutionError> {
        self.execute_with_controls(target, request, Some(credential), Some(cancellation))
            .await
    }

    async fn execute_with_controls(
        &self,
        target: &ApprovedTarget,
        request: &NativeRequestRecord,
        credential: Option<&EphemeralCredential>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<ExecutedResponse, HttpExecutionError> {
        request
            .validate(target)
            .map_err(|_| HttpExecutionError::InvalidRequest)?;
        let execution_started_at = Instant::now();
        let method = request_method(request.method)?;
        let mut current_url =
            Url::parse(&request.url).map_err(|_| HttpExecutionError::InvalidRequest)?;

        for redirect_count in 0..=self.limits.max_redirects {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return Err(HttpExecutionError::Cancelled);
            }
            if !target.contains_url(current_url.as_str()) {
                return Err(HttpExecutionError::RedirectOutOfScope);
            }
            let host = current_url
                .host_str()
                .ok_or(HttpExecutionError::InvalidRequest)?;
            let port = current_url
                .port_or_known_default()
                .ok_or(HttpExecutionError::InvalidRequest)?;
            let addresses = match cancellation {
                Some(cancellation) => {
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => Err(HttpExecutionError::Cancelled),
                        result = self.resolver.resolve(host, port) => result,
                    }
                }
                None => self.resolver.resolve(host, port).await,
            }?;
            if addresses.iter().any(|address| address.port() != port) {
                return Err(HttpExecutionError::ForbiddenDestination);
            }
            if addresses
                .iter()
                .any(|address| !self.address_policy.allows(address.ip()))
            {
                return Err(HttpExecutionError::ForbiddenDestination);
            }
            let selected = *addresses
                .first()
                .ok_or(HttpExecutionError::DnsResolutionFailed)?;
            let client = build_client(host, selected, self.limits)?;
            let mut builder = client
                .request(method.clone(), current_url.clone())
                .header(reqwest::header::USER_AGENT, USER_AGENT);
            for header in &request.headers {
                let (name, value) = outbound_header(header)?;
                builder = builder.header(name, value);
            }
            if let Some(credential) = credential {
                let (name, value) = credential.header_for_url(&target.target_id, &current_url)?;
                builder = builder.header(name, value);
            }

            let send_result = match cancellation {
                Some(cancellation) => {
                    tokio::select! {
                        biased;
                        _ = cancellation.cancelled() => return Err(HttpExecutionError::Cancelled),
                        result = builder.send() => result,
                    }
                }
                None => builder.send().await,
            };
            let mut response = send_result.map_err(classify_reqwest_error)?;
            let remote_address = response
                .remote_addr()
                .filter(|address| address.ip() == selected.ip())
                .ok_or(HttpExecutionError::ForbiddenDestination)?;

            if is_redirect(response.status()) {
                if redirect_count == self.limits.max_redirects {
                    return Err(HttpExecutionError::RedirectLimitExceeded);
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or(HttpExecutionError::RedirectMissingLocation)?;
                let next = current_url
                    .join(location)
                    .map_err(|_| HttpExecutionError::RedirectMissingLocation)?;
                if !target.contains_url(next.as_str()) {
                    return Err(HttpExecutionError::RedirectOutOfScope);
                }
                current_url = next;
                continue;
            }

            if response
                .content_length()
                .is_some_and(|length| length > self.limits.max_response_bytes)
            {
                return Err(HttpExecutionError::ResponseTooLarge);
            }
            let detection_headers = response
                .headers()
                .iter()
                .map(|(name, value)| DetectionHeader {
                    name: name.as_str().to_string(),
                    value: detection_header_value(name.as_str(), value),
                })
                .collect::<Vec<_>>();
            let response_headers = response
                .headers()
                .iter()
                .map(|(name, value)| {
                    HeaderRecord::new(name.as_str(), value.to_str().unwrap_or("[NON-UTF8]"))
                        .map_err(|_| HttpExecutionError::ResponseRecordInvalid)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let status_code = response.status().as_u16();
            let mut body = Vec::new();
            loop {
                let chunk_result = match cancellation {
                    Some(cancellation) => {
                        tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => return Err(HttpExecutionError::Cancelled),
                            result = response.chunk() => result,
                        }
                    }
                    None => response.chunk().await,
                };
                let Some(chunk) =
                    chunk_result.map_err(|_| HttpExecutionError::TlsOrProtocolFailed)?
                else {
                    break;
                };
                if body.len().saturating_add(chunk.len()) > self.limits.max_response_bytes as usize
                {
                    return Err(HttpExecutionError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            let exact_secrets = credential
                .map(|credential| vec![credential.secret()])
                .unwrap_or_default();
            let payload = PayloadSummary::from_bytes_with_redactions(&body, false, &exact_secrets)
                .map_err(|_| HttpExecutionError::ResponseRecordInvalid)?;
            let record = NativeResponseRecord {
                status_code,
                final_url: current_url.to_string(),
                headers: response_headers,
                payload,
                duration_millis: execution_started_at.elapsed().as_millis().min(10_000) as u64,
            };
            record
                .validate(target)
                .map_err(|_| HttpExecutionError::ResponseRecordInvalid)?;
            return Ok(ExecutedResponse {
                record,
                remote_address,
                detection_headers,
                body: Zeroizing::new(body),
            });
        }
        Err(HttpExecutionError::RedirectLimitExceeded)
    }
}

fn detection_header_value(name: &str, value: &HeaderValue) -> String {
    let value = value.to_str().unwrap_or("[NON-UTF8]");
    let lower = name.to_ascii_lowercase();
    if lower == "set-cookie" {
        return sanitize_set_cookie_for_detection(value);
    }
    if lower == "authorization"
        || lower == "proxy-authorization"
        || lower == "cookie"
        || lower == "x-api-key"
        || lower == "x-auth-token"
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api-key")
    {
        "[REDACTED]".to_string()
    } else {
        value.to_string()
    }
}

fn sanitize_set_cookie_for_detection(value: &str) -> String {
    let mut parts = value.split(';');
    let first = parts.next().unwrap_or_default().trim();
    let name = first
        .split_once('=')
        .map(|(name, _)| name.trim())
        .filter(|name| !name.is_empty())
        .unwrap_or("cookie");
    let mut sanitized = format!("{name}=[REDACTED]");
    for attribute in parts {
        let attribute = attribute.trim();
        if !attribute.is_empty() {
            sanitized.push_str("; ");
            sanitized.push_str(attribute);
        }
    }
    sanitized
}

fn build_client(
    host: &str,
    address: SocketAddr,
    limits: HttpExecutionLimits,
) -> Result<Client, HttpExecutionError> {
    Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .connect_timeout(limits.request_timeout)
        .timeout(limits.request_timeout)
        .resolve(host, address)
        .build()
        .map_err(|_| HttpExecutionError::TlsOrProtocolFailed)
}

fn request_method(method: HttpMethod) -> Result<reqwest::Method, HttpExecutionError> {
    match method {
        HttpMethod::Get => Ok(reqwest::Method::GET),
        HttpMethod::Head => Ok(reqwest::Method::HEAD),
        HttpMethod::Options => Ok(reqwest::Method::OPTIONS),
        HttpMethod::Post => Err(HttpExecutionError::UnsupportedMethod),
    }
}

fn outbound_header(header: &HeaderRecord) -> Result<(HeaderName, HeaderValue), HttpExecutionError> {
    let name = HeaderName::from_bytes(header.name.as_bytes())
        .map_err(|_| HttpExecutionError::UnsupportedHeader)?;
    if !matches!(name, ACCEPT | ACCEPT_LANGUAGE | CACHE_CONTROL) {
        return Err(HttpExecutionError::UnsupportedHeader);
    }
    let value = HeaderValue::from_str(header.value.as_str())
        .map_err(|_| HttpExecutionError::UnsupportedHeader)?;
    Ok((name, value))
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn classify_reqwest_error(error: reqwest::Error) -> HttpExecutionError {
    if error.is_connect() || error.is_timeout() {
        HttpExecutionError::ConnectionFailed
    } else {
        HttpExecutionError::TlsOrProtocolFailed
    }
}

fn classify_ipv4(address: Ipv4Addr) -> DestinationClass {
    let [first, second, third, _fourth] = address.octets();
    if address.is_unspecified() || first == 0 {
        DestinationClass::Unspecified
    } else if address.is_loopback() {
        DestinationClass::Loopback
    } else if address.is_private() {
        DestinationClass::Private
    } else if first == 100 && (64..=127).contains(&second) {
        DestinationClass::Shared
    } else if address.is_link_local() {
        DestinationClass::LinkLocal
    } else if (first == 192 && second == 0 && third == 2)
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
    {
        DestinationClass::Documentation
    } else if first == 198 && matches!(second, 18 | 19) {
        DestinationClass::Benchmark
    } else if address.is_multicast() {
        DestinationClass::Multicast
    } else if address.is_broadcast()
        || first >= 240
        || (first == 192 && second == 0 && third == 0)
        || (first == 192 && second == 88 && third == 99)
    {
        DestinationClass::Reserved
    } else {
        DestinationClass::Public
    }
}

fn classify_ipv6(address: Ipv6Addr) -> DestinationClass {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return classify_ipv4(mapped);
    }
    if address.is_unspecified() {
        DestinationClass::Unspecified
    } else if address.is_loopback() {
        DestinationClass::Loopback
    } else if has_ipv6_prefix(address, 0x7e, 7) || has_ipv6_prefix(address, 0x3fb, 10) {
        DestinationClass::Private
    } else if has_ipv6_prefix(address, 0x3fa, 10) {
        DestinationClass::LinkLocal
    } else if has_ipv6_prefix(address, 0x20010db8, 32) {
        DestinationClass::Documentation
    } else if has_ipv6_prefix(address, 0x200100020000, 48) {
        DestinationClass::Benchmark
    } else if address.is_multicast() {
        DestinationClass::Multicast
    } else if has_ipv6_prefix(address, 0x0064ff9b0000000000000000, 96)
        || has_ipv6_prefix(address, 0x0064ff9b0001, 48)
        || has_ipv6_prefix(address, 0x20010000, 32)
        || has_ipv6_prefix(address, 0x2002, 16)
    {
        DestinationClass::Translation
    } else if has_ipv6_prefix(address, 0x0100000000000000, 64)
        || !has_ipv6_prefix(address, 0b001, 3)
    {
        DestinationClass::Reserved
    } else {
        DestinationClass::Public
    }
}

fn has_ipv6_prefix(address: Ipv6Addr, prefix: u128, bits: u32) -> bool {
    let address = u128::from(address);
    let shift = 128 - bits;
    address >> shift == prefix
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use aegis_native_engine::{
        ApprovedTarget, HeaderRecord, HttpMethod, NativeRequestRecord, RequestPurpose,
    };
    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{oneshot, Mutex};

    use super::{
        classify_destination, AddressPolicy, DestinationClass, DnsResolver, HttpExecutionError,
        HttpExecutionLimits, NativeHttpExecutor, PublicAddressPolicy,
    };

    #[derive(Clone)]
    struct FixedResolver {
        address: SocketAddr,
    }

    #[async_trait]
    impl DnsResolver for FixedResolver {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Vec<SocketAddr>, HttpExecutionError> {
            Ok(vec![self.address])
        }
    }

    #[derive(Clone, Copy)]
    struct TestAddressPolicy;

    impl AddressPolicy for TestAddressPolicy {
        fn allows(&self, _address: IpAddr) -> bool {
            true
        }
    }

    fn request(url: String) -> NativeRequestRecord {
        NativeRequestRecord {
            request_id: "request-1".to_string(),
            target_id: "target-1".to_string(),
            method: HttpMethod::Get,
            url,
            purpose: RequestPurpose::Probe,
            headers: vec![HeaderRecord::new("Accept", "application/json").unwrap()],
            payload: None,
            credential_ref: None,
        }
    }

    async fn mock_server(responses: Vec<Vec<u8>>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let responses = Arc::new(Mutex::new(responses.into_iter()));
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let responses = Arc::clone(&responses);
                tokio::spawn(async move {
                    let mut request_buffer = [0u8; 2048];
                    let _ = stream.read(&mut request_buffer).await;
                    if let Some(response) = responses.lock().await.next() {
                        let _ = stream.write_all(&response).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        address
    }

    async fn capture_server(response: Vec<u8>) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_for_task = Arc::clone(&captured);
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request_buffer = vec![0u8; 4096];
            let bytes_read = stream.read(&mut request_buffer).await.unwrap();
            captured_for_task
                .lock()
                .await
                .extend_from_slice(&request_buffer[..bytes_read]);
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        (address, captured)
    }

    fn approved_target(port: u16) -> ApprovedTarget {
        ApprovedTarget::new("target-1", format!("http://example.test:{port}"), "/").unwrap()
    }

    #[tokio::test]
    async fn executes_bounded_response_with_pinned_resolution() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nSet-Cookie: session=secret\r\n\r\nhello world".to_vec();
        let address = mock_server(vec![response]).await;
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            TestAddressPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = approved_target(address.port());
        let executed = executor
            .execute(
                &target,
                &request(format!("http://example.test:{}/", address.port())),
            )
            .await
            .unwrap();
        assert_eq!(executed.body(), b"hello world");
        assert_eq!(executed.remote_address.ip(), address.ip());
        assert!(executed
            .record
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("set-cookie"))
            .is_some_and(|header| header.value.as_str() == "[REDACTED]"));
    }

    #[tokio::test]
    async fn follows_only_same_scope_redirects() {
        let first = b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n".to_vec();
        let second = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let address = mock_server(vec![first, second]).await;
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            TestAddressPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = approved_target(address.port());
        let executed = executor
            .execute(
                &target,
                &request(format!("http://example.test:{}/start", address.port())),
            )
            .await
            .unwrap();
        assert!(executed.record.final_url.ends_with("/final"));

        let external =
            b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n"
                .to_vec();
        let address = mock_server(vec![external]).await;
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            TestAddressPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = approved_target(address.port());
        let error = executor
            .execute(
                &target,
                &request(format!("http://example.test:{}/start", address.port())),
            )
            .await
            .unwrap_err();
        assert_eq!(error, HttpExecutionError::RedirectOutOfScope);
    }

    #[tokio::test]
    async fn rejects_stream_that_exceeds_response_limit() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n123456".to_vec();
        let address = mock_server(vec![response]).await;
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            TestAddressPolicy,
            HttpExecutionLimits {
                max_response_bytes: 5,
                ..HttpExecutionLimits::default()
            },
        )
        .unwrap();
        let target = approved_target(address.port());
        let error = executor
            .execute(
                &target,
                &request(format!("http://example.test:{}/", address.port())),
            )
            .await
            .unwrap_err();
        assert_eq!(error, HttpExecutionError::ResponseTooLarge);
    }

    #[tokio::test]
    async fn timeout_does_not_expose_internal_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            TestAddressPolicy,
            HttpExecutionLimits {
                request_timeout: Duration::from_millis(50),
                ..HttpExecutionLimits::default()
            },
        )
        .unwrap();
        let target = approved_target(address.port());
        let error = executor
            .execute(
                &target,
                &request(format!("http://example.test:{}/", address.port())),
            )
            .await
            .unwrap_err();
        assert_eq!(error, HttpExecutionError::ConnectionFailed);
        assert!(!error.to_string().contains("example.test"));
    }

    #[test]
    fn public_policy_rejects_local_private_link_local_and_metadata_addresses() {
        let policy = PublicAddressPolicy;
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(!policy.allows(address.parse().unwrap()), "{address}");
        }
        assert!(policy.allows(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn classifies_special_ipv4_and_ipv6_ranges() {
        let cases = [
            ("100.64.0.1", DestinationClass::Shared),
            ("192.0.2.1", DestinationClass::Documentation),
            ("198.18.0.1", DestinationClass::Benchmark),
            ("240.0.0.1", DestinationClass::Reserved),
            ("2001:db8::1", DestinationClass::Documentation),
            ("2001:2::1", DestinationClass::Benchmark),
            ("2002::1", DestinationClass::Translation),
            ("64:ff9b::1", DestinationClass::Translation),
            ("fe80::1", DestinationClass::LinkLocal),
            ("febf::1", DestinationClass::LinkLocal),
            ("fec0::1", DestinationClass::Private),
            ("feff::1", DestinationClass::Private),
            ("fe7f::1", DestinationClass::Reserved),
            ("2001:4860:4860::8888", DestinationClass::Public),
        ];
        for (address, expected) in cases {
            assert_eq!(
                classify_destination(address.parse().unwrap()),
                expected,
                "{address}"
            );
        }
    }

    #[tokio::test]
    async fn any_forbidden_dns_answer_blocks_connection() {
        #[derive(Clone)]
        struct MixedResolver;

        #[async_trait]
        impl DnsResolver for MixedResolver {
            async fn resolve(
                &self,
                _host: &str,
                port: u16,
            ) -> Result<Vec<SocketAddr>, HttpExecutionError> {
                Ok(vec![
                    SocketAddr::new("8.8.8.8".parse().unwrap(), port),
                    SocketAddr::new("127.0.0.1".parse().unwrap(), port),
                ])
            }
        }

        let executor = NativeHttpExecutor::new(
            MixedResolver,
            PublicAddressPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = ApprovedTarget::new("target-1", "https://example.com", "/").unwrap();
        let error = executor
            .execute(&target, &request("https://example.com/".to_string()))
            .await
            .unwrap_err();
        assert_eq!(error, HttpExecutionError::ForbiddenDestination);
    }

    #[tokio::test]
    async fn dns_rebinding_on_same_host_redirect_is_blocked_before_second_connection() {
        #[derive(Clone)]
        struct SequenceResolver {
            answers: Arc<Mutex<std::vec::IntoIter<SocketAddr>>>,
        }

        #[async_trait]
        impl DnsResolver for SequenceResolver {
            async fn resolve(
                &self,
                _host: &str,
                _port: u16,
            ) -> Result<Vec<SocketAddr>, HttpExecutionError> {
                self.answers
                    .lock()
                    .await
                    .next()
                    .map(|address| vec![address])
                    .ok_or(HttpExecutionError::DnsResolutionFailed)
            }
        }

        #[derive(Clone, Copy)]
        struct RebindingTestPolicy;

        impl AddressPolicy for RebindingTestPolicy {
            fn allows(&self, address: IpAddr) -> bool {
                address.is_loopback()
            }
        }

        let redirect =
            b"HTTP/1.1 302 Found\r\nLocation: /second\r\nContent-Length: 0\r\n\r\n".to_vec();
        let first_address = mock_server(vec![redirect]).await;
        let rebound_address = SocketAddr::new("10.0.0.8".parse().unwrap(), first_address.port());
        let resolver = SequenceResolver {
            answers: Arc::new(Mutex::new(vec![first_address, rebound_address].into_iter())),
        };
        let executor = NativeHttpExecutor::new(
            resolver,
            RebindingTestPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = approved_target(first_address.port());
        let error = executor
            .execute(
                &target,
                &request(format!(
                    "http://example.test:{}/first",
                    first_address.port()
                )),
            )
            .await
            .unwrap_err();
        assert_eq!(error, HttpExecutionError::ForbiddenDestination);
    }

    #[tokio::test]
    async fn resolver_cannot_replace_approved_port() {
        let address = SocketAddr::new("8.8.8.8".parse().unwrap(), 4444);
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            PublicAddressPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = ApprovedTarget::new("target-1", "https://example.com", "/").unwrap();
        let error = executor
            .execute(&target, &request("https://example.com/".to_string()))
            .await
            .unwrap_err();
        assert_eq!(error, HttpExecutionError::ForbiddenDestination);
    }

    #[tokio::test]
    async fn injects_ephemeral_bearer_only_in_memory_and_redacts_reflection() {
        let secret = "top-secret-token";
        let body = format!("reflected={secret}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes();
        let (address, captured) = capture_server(response).await;
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            TestAddressPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = approved_target(address.port());
        let scope = crate::credential::CredentialScope::for_http_test(&target, "/").unwrap();
        let credential = crate::EphemeralCredential::new(
            crate::CredentialKind::BearerToken,
            scope,
            secret.to_string(),
        )
        .unwrap();
        let mut request = request(format!("http://example.test:{}/", address.port()));
        request.credential_ref = Some("credential-1".to_string());
        let executed = executor
            .execute_authenticated(&target, &request, &credential)
            .await
            .unwrap();

        let sent = String::from_utf8(captured.lock().await.clone()).unwrap();
        assert!(sent
            .to_ascii_lowercase()
            .contains("authorization: bearer top-secret-token"));
        assert!(executed
            .body()
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()));
        assert!(!executed
            .record
            .payload
            .redacted_excerpt
            .as_str()
            .contains(secret));
        assert!(!serde_json::to_string(&executed.record)
            .unwrap()
            .contains(secret));
        assert!(!format!("{executed:?}").contains(secret));
    }

    #[tokio::test]
    async fn credential_path_scope_is_checked_before_sending() {
        let address = mock_server(vec![]).await;
        let executor = NativeHttpExecutor::new(
            FixedResolver { address },
            TestAddressPolicy,
            HttpExecutionLimits::default(),
        )
        .unwrap();
        let target = approved_target(address.port());
        let scope = crate::credential::CredentialScope::for_http_test(&target, "/private").unwrap();
        let credential = crate::EphemeralCredential::new(
            crate::CredentialKind::CookieSession,
            scope,
            "session=safe".to_string(),
        )
        .unwrap();
        let error = executor
            .execute_authenticated(
                &target,
                &request(format!("http://example.test:{}/public", address.port())),
                &credential,
            )
            .await
            .unwrap_err();
        assert_eq!(error, HttpExecutionError::CredentialScopeMismatch);
    }

    #[tokio::test]
    async fn cancellation_aborts_in_flight_response_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (headers_sent, headers_received) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request_buffer = [0u8; 2048];
            let _ = stream.read(&mut request_buffer).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
                .await
                .unwrap();
            let _ = headers_sent.send(());
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let executor = Arc::new(
            NativeHttpExecutor::new(
                FixedResolver { address },
                TestAddressPolicy,
                HttpExecutionLimits::default(),
            )
            .unwrap(),
        );
        let target = approved_target(address.port());
        let request = request(format!("http://example.test:{}/", address.port()));
        let cancellation = crate::CancellationToken::new();
        let task_executor = Arc::clone(&executor);
        let task_cancellation = cancellation.clone();
        let execution = tokio::spawn(async move {
            task_executor
                .execute_cancellable(&target, &request, &task_cancellation)
                .await
        });

        headers_received.await.unwrap();
        cancellation.cancel();
        assert_eq!(
            execution.await.unwrap().unwrap_err(),
            HttpExecutionError::Cancelled
        );
    }
}
