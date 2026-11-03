use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use aegis_native_engine::{ApprovedTarget, HttpMethod, NativeRequestRecord, RequestPurpose};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use crate::credential::CredentialScope;
use crate::{
    AddressPolicy, CredentialKind, DnsResolver, EphemeralCredential, ExecutionRuntimeConfig,
    HttpExecutionError, HttpExecutionLimits, NativeHttpExecutor, RequestActivity,
    RuntimeControlError, TargetExecutionGate,
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
struct LoopbackFixturePolicy;

impl AddressPolicy for LoopbackFixturePolicy {
    fn allows(&self, address: IpAddr) -> bool {
        address.is_loopback()
    }
}

struct ScriptedTarget {
    address: SocketAddr,
    captured_requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl ScriptedTarget {
    async fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured_requests = Arc::new(Mutex::new(Vec::new()));
        let captured_for_task = Arc::clone(&captured_requests);
        tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0u8; 8_192];
                let bytes_read = stream.read(&mut request).await.unwrap();
                request.truncate(bytes_read);
                captured_for_task.lock().await.push(request);
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self {
            address,
            captured_requests,
        }
    }

    fn target(&self, path_prefix: &str) -> ApprovedTarget {
        ApprovedTarget::new(
            "target-1",
            format!("http://fixture.test:{}", self.address.port()),
            path_prefix,
        )
        .unwrap()
    }

    fn executor(
        &self,
        limits: HttpExecutionLimits,
    ) -> NativeHttpExecutor<FixedResolver, LoopbackFixturePolicy> {
        NativeHttpExecutor::new(
            FixedResolver {
                address: self.address,
            },
            LoopbackFixturePolicy,
            limits,
        )
        .unwrap()
    }

    async fn request_count(&self) -> usize {
        self.captured_requests.lock().await.len()
    }

    async fn request_text(&self, index: usize) -> String {
        String::from_utf8(self.captured_requests.lock().await[index].clone()).unwrap()
    }
}

fn request(target: &ApprovedTarget, id: &str, path: &str) -> NativeRequestRecord {
    NativeRequestRecord {
        request_id: id.to_string(),
        target_id: target.target_id.clone(),
        method: HttpMethod::Get,
        url: format!("{}{}", target.origin, path),
        purpose: RequestPurpose::Probe,
        headers: Vec::new(),
        payload: None,
        credential_ref: None,
    }
}

#[tokio::test]
async fn redirect_loop_stops_at_hard_limit() {
    let redirect = b"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n".to_vec();
    let fixture = ScriptedTarget::start(vec![redirect; 6]).await;
    let target = fixture.target("/");
    let error = fixture
        .executor(HttpExecutionLimits::default())
        .execute(&target, &request(&target, "redirect", "/loop"))
        .await
        .unwrap_err();

    assert_eq!(error, HttpExecutionError::RedirectLimitExceeded);
    assert_eq!(fixture.request_count().await, 6);
}

#[tokio::test]
async fn credential_scope_exit_blocks_second_redirect_request() {
    let redirect = b"HTTP/1.1 302 Found\r\nLocation: /public\r\nContent-Length: 0\r\n\r\n".to_vec();
    let fixture = ScriptedTarget::start(vec![redirect]).await;
    let target = fixture.target("/");
    let credential = EphemeralCredential::new(
        CredentialKind::BearerToken,
        CredentialScope::for_http_test(&target, "/private").unwrap(),
        "redirect-secret".to_string(),
    )
    .unwrap();
    let mut request = request(&target, "credential-redirect", "/private/start");
    request.credential_ref = Some("credential-1".to_string());

    let error = fixture
        .executor(HttpExecutionLimits::default())
        .execute_authenticated(&target, &request, &credential)
        .await
        .unwrap_err();
    assert_eq!(error, HttpExecutionError::CredentialScopeMismatch);
    assert_eq!(fixture.request_count().await, 1);
    assert!(fixture
        .request_text(0)
        .await
        .to_ascii_lowercase()
        .contains("authorization: bearer redirect-secret"));
}

#[tokio::test]
async fn streamed_body_without_content_length_still_obeys_limit() {
    let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n123456".to_vec();
    let fixture = ScriptedTarget::start(vec![response]).await;
    let target = fixture.target("/");
    let limits = HttpExecutionLimits {
        max_response_bytes: 5,
        ..HttpExecutionLimits::default()
    };
    let error = fixture
        .executor(limits)
        .execute(&target, &request(&target, "stream-limit", "/body"))
        .await
        .unwrap_err();

    assert_eq!(error, HttpExecutionError::ResponseTooLarge);
}

#[tokio::test]
async fn every_credential_kind_is_absent_from_record_and_debug_output() {
    let cases = [
        (CredentialKind::BearerToken, "bearer-secret"),
        (
            CredentialKind::ApiKeyHeader {
                header_name: "X-Test-Key".to_string(),
            },
            "api-key-secret",
        ),
        (CredentialKind::CookieSession, "session=cookie-secret"),
    ];

    for (index, (kind, secret)) in cases.into_iter().enumerate() {
        let body = format!("reflected:{secret}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let fixture = ScriptedTarget::start(vec![response]).await;
        let target = fixture.target("/");
        let credential = EphemeralCredential::new(
            kind,
            CredentialScope::for_http_test(&target, "/").unwrap(),
            secret.to_string(),
        )
        .unwrap();
        let mut request = request(&target, &format!("secret-{index}"), "/reflect");
        request.credential_ref = Some(format!("credential-{index}"));
        let executed = fixture
            .executor(HttpExecutionLimits::default())
            .execute_authenticated(&target, &request, &credential)
            .await
            .unwrap();

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
}

#[tokio::test]
async fn target_gates_isolate_budget_and_cancellation_state() {
    let target_a = ApprovedTarget::new("target-a", "https://a.example", "/").unwrap();
    let target_b = ApprovedTarget::new("target-b", "https://b.example", "/").unwrap();
    let limits = ExecutionRuntimeConfig {
        max_requests: 1,
        max_discovery_requests: 1,
        max_active_requests: 1,
        max_mutations_per_endpoint: 1,
        requests_per_second: 1,
        burst: 1,
        max_concurrency: 1,
        queue_capacity: 1,
    };
    let gate_a = TargetExecutionGate::new(&target_a, limits).unwrap();
    let gate_b = TargetExecutionGate::new(&target_b, limits).unwrap();
    let request_a = request(&target_a, "a-1", "/probe");
    let request_b = NativeRequestRecord {
        request_id: "b-1".to_string(),
        target_id: target_b.target_id.clone(),
        url: format!("{}/probe", target_b.origin),
        ..request(&target_b, "b-1", "/probe")
    };

    drop(
        gate_a
            .admit(&request_a, RequestActivity::Standard)
            .await
            .unwrap(),
    );
    assert_eq!(
        gate_a
            .admit(&request_a, RequestActivity::Standard)
            .await
            .unwrap_err(),
        RuntimeControlError::TotalBudgetExhausted
    );
    gate_a.cancel();
    assert!(gate_a.cancellation_token().is_cancelled());
    assert!(!gate_b.cancellation_token().is_cancelled());
    assert!(gate_b
        .admit(&request_b, RequestActivity::Standard)
        .await
        .is_ok());
    assert_eq!(gate_b.budget_snapshot().await.total, 1);
}
