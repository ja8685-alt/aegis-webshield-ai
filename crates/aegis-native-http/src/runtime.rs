use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use aegis_native_engine::{ApprovedTarget, HttpMethod, NativeRequestRecord, RequestPurpose};
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use url::Url;

const POLICY_MAX_REQUESTS: u32 = 500;
const POLICY_MAX_DISCOVERY_REQUESTS: u32 = 300;
const POLICY_MAX_ACTIVE_REQUESTS: u32 = 200;
const POLICY_MAX_MUTATIONS_PER_ENDPOINT: u16 = 12;
const POLICY_MAX_REQUESTS_PER_SECOND: u32 = 2;
const POLICY_MAX_BURST: u32 = 4;
const POLICY_MAX_CONCURRENCY: usize = 4;
const POLICY_MAX_QUEUE_CAPACITY: usize = 256;

/// Whether a request is an ordinary exchange or an active input mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestActivity {
    Standard,
    Mutation,
}

/// D-146 hard limits, optionally narrowed for a customer plan or scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionRuntimeConfig {
    pub max_requests: u32,
    pub max_discovery_requests: u32,
    pub max_active_requests: u32,
    pub max_mutations_per_endpoint: u16,
    pub requests_per_second: u32,
    pub burst: u32,
    pub max_concurrency: usize,
    pub queue_capacity: usize,
}

impl Default for ExecutionRuntimeConfig {
    fn default() -> Self {
        Self {
            max_requests: POLICY_MAX_REQUESTS,
            max_discovery_requests: POLICY_MAX_DISCOVERY_REQUESTS,
            max_active_requests: POLICY_MAX_ACTIVE_REQUESTS,
            max_mutations_per_endpoint: POLICY_MAX_MUTATIONS_PER_ENDPOINT,
            requests_per_second: POLICY_MAX_REQUESTS_PER_SECOND,
            burst: POLICY_MAX_BURST,
            max_concurrency: POLICY_MAX_CONCURRENCY,
            queue_capacity: 64,
        }
    }
}

impl ExecutionRuntimeConfig {
    pub fn validate(&self) -> Result<(), RuntimeControlError> {
        if self.max_requests == 0
            || self.max_requests > POLICY_MAX_REQUESTS
            || self.max_discovery_requests == 0
            || self.max_discovery_requests > POLICY_MAX_DISCOVERY_REQUESTS
            || self.max_discovery_requests > self.max_requests
            || self.max_active_requests == 0
            || self.max_active_requests > POLICY_MAX_ACTIVE_REQUESTS
            || self.max_active_requests > self.max_requests
            || self.max_mutations_per_endpoint == 0
            || self.max_mutations_per_endpoint > POLICY_MAX_MUTATIONS_PER_ENDPOINT
            || self.requests_per_second == 0
            || self.requests_per_second > POLICY_MAX_REQUESTS_PER_SECOND
            || self.burst == 0
            || self.burst > POLICY_MAX_BURST
            || self.max_concurrency == 0
            || self.max_concurrency > POLICY_MAX_CONCURRENCY
            || self.queue_capacity == 0
            || self.queue_capacity > POLICY_MAX_QUEUE_CAPACITY
        {
            return Err(RuntimeControlError::InvalidConfig);
        }
        Ok(())
    }
}

/// Sanitized runtime errors that contain no target URL, payload, or credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeControlError {
    InvalidConfig,
    InvalidRequest,
    TargetMismatch,
    InvalidActivity,
    TotalBudgetExhausted,
    DiscoveryBudgetExhausted,
    ActiveBudgetExhausted,
    MutationBudgetExhausted,
    Cancelled,
    QueueClosed,
}

impl Display for RuntimeControlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidConfig => "runtime limits are invalid",
            Self::InvalidRequest => "request cannot be admitted",
            Self::TargetMismatch => "request target does not match the execution gate",
            Self::InvalidActivity => "request activity does not match its purpose",
            Self::TotalBudgetExhausted => "scan request budget exhausted",
            Self::DiscoveryBudgetExhausted => "discovery request budget exhausted",
            Self::ActiveBudgetExhausted => "active request budget exhausted",
            Self::MutationBudgetExhausted => "endpoint mutation budget exhausted",
            Self::Cancelled => "execution cancelled",
            Self::QueueClosed => "work queue closed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RuntimeControlError {}

/// One-way scan cancellation signal shared by producers, gates, and the HTTP adapter.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    sender: Arc<watch::Sender<bool>>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
        }
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        if *receiver.borrow() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow() {
                return;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestBudgetSnapshot {
    pub total: u32,
    pub discovery: u32,
    pub active: u32,
    pub mutated_endpoints: usize,
}

#[derive(Default)]
struct RequestBudgetState {
    total: u32,
    discovery: u32,
    active: u32,
    mutations_by_endpoint: HashMap<String, u16>,
}

struct RequestBudget {
    config: ExecutionRuntimeConfig,
    state: Mutex<RequestBudgetState>,
}

impl RequestBudget {
    async fn reserve(
        &self,
        request: &NativeRequestRecord,
        activity: RequestActivity,
    ) -> Result<(), RuntimeControlError> {
        validate_activity(request.purpose, activity)?;
        let mutation_key = if activity == RequestActivity::Mutation {
            Some(endpoint_key(request)?)
        } else {
            None
        };
        let is_discovery = request.purpose == RequestPurpose::Discovery;
        let is_active = matches!(
            request.purpose,
            RequestPurpose::Probe | RequestPurpose::Control
        );
        let mut state = self.state.lock().await;

        if state.total >= self.config.max_requests {
            return Err(RuntimeControlError::TotalBudgetExhausted);
        }
        if is_discovery && state.discovery >= self.config.max_discovery_requests {
            return Err(RuntimeControlError::DiscoveryBudgetExhausted);
        }
        if is_active && state.active >= self.config.max_active_requests {
            return Err(RuntimeControlError::ActiveBudgetExhausted);
        }
        if let Some(key) = mutation_key.as_ref() {
            if state.mutations_by_endpoint.get(key).copied().unwrap_or(0)
                >= self.config.max_mutations_per_endpoint
            {
                return Err(RuntimeControlError::MutationBudgetExhausted);
            }
        }

        state.total += 1;
        if is_discovery {
            state.discovery += 1;
        }
        if is_active {
            state.active += 1;
        }
        if let Some(key) = mutation_key {
            *state.mutations_by_endpoint.entry(key).or_default() += 1;
        }
        Ok(())
    }

    async fn snapshot(&self) -> RequestBudgetSnapshot {
        let state = self.state.lock().await;
        RequestBudgetSnapshot {
            total: state.total,
            discovery: state.discovery,
            active: state.active,
            mutated_endpoints: state.mutations_by_endpoint.len(),
        }
    }
}

struct TokenBucketState {
    tokens: f64,
    last_refill: Instant,
}

struct TokenBucket {
    rate: f64,
    capacity: f64,
    state: Mutex<TokenBucketState>,
}

impl TokenBucket {
    fn new(rate: u32, capacity: u32) -> Self {
        Self {
            rate: f64::from(rate),
            capacity: f64::from(capacity),
            state: Mutex::new(TokenBucketState {
                tokens: f64::from(capacity),
                last_refill: Instant::now(),
            }),
        }
    }

    async fn acquire(&self, cancellation: &CancellationToken) -> Result<(), RuntimeControlError> {
        loop {
            if cancellation.is_cancelled() {
                return Err(RuntimeControlError::Cancelled);
            }
            let wait = {
                let mut state = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill).as_secs_f64();
                state.tokens = (state.tokens + elapsed * self.rate).min(self.capacity);
                state.last_refill = now;
                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    return Ok(());
                }
                Duration::from_secs_f64((1.0 - state.tokens) / self.rate)
            };
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Err(RuntimeControlError::Cancelled),
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

/// Per-target admission controller. Create a separate instance for every scan target.
#[derive(Clone)]
pub struct TargetExecutionGate {
    target: ApprovedTarget,
    config: ExecutionRuntimeConfig,
    budget: Arc<RequestBudget>,
    rate_limiter: Arc<TokenBucket>,
    concurrency: Arc<Semaphore>,
    cancellation: CancellationToken,
}

impl TargetExecutionGate {
    pub fn new(
        target: &ApprovedTarget,
        config: ExecutionRuntimeConfig,
    ) -> Result<Self, RuntimeControlError> {
        config.validate()?;
        target
            .validate()
            .map_err(|_| RuntimeControlError::InvalidRequest)?;
        Ok(Self {
            target: target.clone(),
            config,
            budget: Arc::new(RequestBudget {
                config,
                state: Mutex::new(RequestBudgetState::default()),
            }),
            rate_limiter: Arc::new(TokenBucket::new(config.requests_per_second, config.burst)),
            concurrency: Arc::new(Semaphore::new(config.max_concurrency)),
            cancellation: CancellationToken::new(),
        })
    }

    pub async fn admit(
        &self,
        request: &NativeRequestRecord,
        activity: RequestActivity,
    ) -> Result<ExecutionPermit, RuntimeControlError> {
        if self.cancellation.is_cancelled() {
            return Err(RuntimeControlError::Cancelled);
        }
        if request.target_id != self.target.target_id {
            return Err(RuntimeControlError::TargetMismatch);
        }
        request
            .validate(&self.target)
            .map_err(|_| RuntimeControlError::InvalidRequest)?;
        self.budget.reserve(request, activity).await?;
        self.rate_limiter.acquire(&self.cancellation).await?;
        let permit = tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => return Err(RuntimeControlError::Cancelled),
            permit = Arc::clone(&self.concurrency).acquire_owned() => {
                permit.map_err(|_| RuntimeControlError::Cancelled)?
            }
        };
        Ok(ExecutionPermit { _permit: permit })
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn queue<T>(&self) -> (WorkSender<T>, WorkReceiver<T>) {
        bounded_work_queue(self.config.queue_capacity, self.cancellation.clone())
            .expect("validated queue capacity")
    }

    pub async fn budget_snapshot(&self) -> RequestBudgetSnapshot {
        self.budget.snapshot().await
    }
}

/// RAII concurrency slot released as soon as the request attempt finishes.
#[derive(Debug)]
pub struct ExecutionPermit {
    _permit: OwnedSemaphorePermit,
}

/// Bounded producer handle. `send` waits when the worker is slower than discovery.
#[derive(Clone)]
pub struct WorkSender<T> {
    sender: mpsc::Sender<T>,
    cancellation: CancellationToken,
}

impl<T> WorkSender<T> {
    pub async fn send(&self, item: T) -> Result<(), RuntimeControlError> {
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(RuntimeControlError::Cancelled),
            result = self.sender.send(item) => result.map_err(|_| RuntimeControlError::QueueClosed),
        }
    }
}

/// Single-consumer bounded queue handle.
pub struct WorkReceiver<T> {
    receiver: mpsc::Receiver<T>,
    cancellation: CancellationToken,
}

impl<T> WorkReceiver<T> {
    pub async fn recv(&mut self) -> Result<Option<T>, RuntimeControlError> {
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(RuntimeControlError::Cancelled),
            item = self.receiver.recv() => Ok(item),
        }
    }
}

pub fn bounded_work_queue<T>(
    capacity: usize,
    cancellation: CancellationToken,
) -> Result<(WorkSender<T>, WorkReceiver<T>), RuntimeControlError> {
    if capacity == 0 || capacity > POLICY_MAX_QUEUE_CAPACITY {
        return Err(RuntimeControlError::InvalidConfig);
    }
    let (sender, receiver) = mpsc::channel(capacity);
    Ok((
        WorkSender {
            sender,
            cancellation: cancellation.clone(),
        },
        WorkReceiver {
            receiver,
            cancellation,
        },
    ))
}

fn validate_activity(
    purpose: RequestPurpose,
    activity: RequestActivity,
) -> Result<(), RuntimeControlError> {
    if activity == RequestActivity::Mutation
        && !matches!(purpose, RequestPurpose::Probe | RequestPurpose::Control)
    {
        return Err(RuntimeControlError::InvalidActivity);
    }
    Ok(())
}

fn endpoint_key(request: &NativeRequestRecord) -> Result<String, RuntimeControlError> {
    let url = Url::parse(&request.url).map_err(|_| RuntimeControlError::InvalidRequest)?;
    let method = match request.method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Post => "POST",
    };
    Ok(format!("{method}:{}", url.path()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aegis_native_engine::{ApprovedTarget, HttpMethod, NativeRequestRecord, RequestPurpose};

    use super::{
        ExecutionRuntimeConfig, RequestActivity, RuntimeControlError, TargetExecutionGate,
    };

    fn target() -> ApprovedTarget {
        ApprovedTarget::new("target-1", "https://example.com", "/").unwrap()
    }

    fn request(id: &str, path: &str, purpose: RequestPurpose) -> NativeRequestRecord {
        NativeRequestRecord {
            request_id: id.to_string(),
            target_id: "target-1".to_string(),
            method: HttpMethod::Get,
            url: format!("https://example.com{path}"),
            purpose,
            headers: Vec::new(),
            payload: None,
            credential_ref: None,
        }
    }

    fn config() -> ExecutionRuntimeConfig {
        ExecutionRuntimeConfig {
            max_requests: 8,
            max_discovery_requests: 4,
            max_active_requests: 4,
            max_mutations_per_endpoint: 2,
            requests_per_second: 2,
            burst: 4,
            max_concurrency: 4,
            queue_capacity: 2,
        }
    }

    #[test]
    fn configuration_can_only_narrow_hard_policy_limits() {
        assert!(ExecutionRuntimeConfig::default().validate().is_ok());
        let invalid = ExecutionRuntimeConfig {
            max_concurrency: 5,
            ..ExecutionRuntimeConfig::default()
        };
        assert_eq!(invalid.validate(), Err(RuntimeControlError::InvalidConfig));
    }

    #[tokio::test]
    async fn budget_reservation_is_atomic_across_total_and_lanes() {
        let mut limits = config();
        limits.max_requests = 2;
        limits.max_discovery_requests = 1;
        limits.max_active_requests = 1;
        let gate = TargetExecutionGate::new(&target(), limits).unwrap();

        drop(
            gate.admit(
                &request("discovery-1", "/one", RequestPurpose::Discovery),
                RequestActivity::Standard,
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            gate.admit(
                &request("discovery-2", "/two", RequestPurpose::Discovery),
                RequestActivity::Standard,
            )
            .await
            .unwrap_err(),
            RuntimeControlError::DiscoveryBudgetExhausted
        );
        drop(
            gate.admit(
                &request("probe-1", "/one", RequestPurpose::Probe),
                RequestActivity::Standard,
            )
            .await
            .unwrap(),
        );
        assert_eq!(gate.budget_snapshot().await.total, 2);
    }

    #[tokio::test]
    async fn mutation_budget_is_scoped_per_method_and_path() {
        let mut limits = config();
        limits.max_mutations_per_endpoint = 1;
        let gate = TargetExecutionGate::new(&target(), limits).unwrap();
        for id in ["mutation-1"] {
            drop(
                gate.admit(
                    &request(id, "/accounts/1", RequestPurpose::Probe),
                    RequestActivity::Mutation,
                )
                .await
                .unwrap(),
            );
        }
        assert_eq!(
            gate.admit(
                &request("mutation-2", "/accounts/1", RequestPurpose::Probe),
                RequestActivity::Mutation,
            )
            .await
            .unwrap_err(),
            RuntimeControlError::MutationBudgetExhausted
        );
        drop(
            gate.admit(
                &request("mutation-3", "/accounts/2", RequestPurpose::Probe),
                RequestActivity::Mutation,
            )
            .await
            .unwrap(),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn token_bucket_honors_burst_and_refill_rate() {
        let mut limits = config();
        limits.burst = 1;
        let gate = TargetExecutionGate::new(&target(), limits).unwrap();
        drop(
            gate.admit(
                &request("first", "/one", RequestPurpose::Baseline),
                RequestActivity::Standard,
            )
            .await
            .unwrap(),
        );

        let pending_gate = gate.clone();
        let pending = tokio::spawn(async move {
            pending_gate
                .admit(
                    &request("second", "/two", RequestPurpose::Baseline),
                    RequestActivity::Standard,
                )
                .await
        });
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        tokio::time::advance(Duration::from_millis(499)).await;
        assert!(!pending.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(pending.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn concurrency_waiter_is_released_by_permit_drop() {
        let mut limits = config();
        limits.max_concurrency = 1;
        let gate = TargetExecutionGate::new(&target(), limits).unwrap();
        let first = gate
            .admit(
                &request("first", "/one", RequestPurpose::Baseline),
                RequestActivity::Standard,
            )
            .await
            .unwrap();
        let pending_gate = gate.clone();
        let pending = tokio::spawn(async move {
            pending_gate
                .admit(
                    &request("second", "/two", RequestPurpose::Baseline),
                    RequestActivity::Standard,
                )
                .await
        });
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        drop(first);
        assert!(pending.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn cancellation_interrupts_concurrency_and_queue_waiters() {
        let mut limits = config();
        limits.max_concurrency = 1;
        limits.queue_capacity = 1;
        let gate = TargetExecutionGate::new(&target(), limits).unwrap();
        let _first = gate
            .admit(
                &request("first", "/one", RequestPurpose::Baseline),
                RequestActivity::Standard,
            )
            .await
            .unwrap();
        let (sender, _receiver) = gate.queue();
        sender.send(1u8).await.unwrap();

        let pending_gate = gate.clone();
        let concurrency_waiter = tokio::spawn(async move {
            pending_gate
                .admit(
                    &request("second", "/two", RequestPurpose::Baseline),
                    RequestActivity::Standard,
                )
                .await
        });
        let queue_waiter = tokio::spawn(async move { sender.send(2u8).await });
        tokio::task::yield_now().await;
        gate.cancel();
        assert_eq!(
            concurrency_waiter.await.unwrap().unwrap_err(),
            RuntimeControlError::Cancelled
        );
        assert_eq!(
            queue_waiter.await.unwrap().unwrap_err(),
            RuntimeControlError::Cancelled
        );
    }

    #[tokio::test]
    async fn bounded_queue_applies_backpressure_until_consumer_receives() {
        let mut limits = config();
        limits.queue_capacity = 1;
        let gate = TargetExecutionGate::new(&target(), limits).unwrap();
        let (sender, mut receiver) = gate.queue();
        sender.send(1u8).await.unwrap();
        let pending = tokio::spawn(async move { sender.send(2u8).await });
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        assert_eq!(receiver.recv().await.unwrap(), Some(1));
        assert!(pending.await.unwrap().is_ok());
        assert_eq!(receiver.recv().await.unwrap(), Some(2));
    }
}
