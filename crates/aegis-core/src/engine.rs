use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineStatus {
    Stopped,
    Starting,
    Ready,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineComponentStatus {
    Ready,
    Pending,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineHealthCheck {
    pub component: String,
    pub status: EngineComponentStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalEngineSnapshot {
    pub status: EngineStatus,
    pub version: String,
    pub bind_address: String,
    pub active_scans: u32,
    pub max_concurrent_scans: u32,
    pub checks: Vec<EngineHealthCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEngineService {
    version: String,
    bind_address: String,
    status: EngineStatus,
    active_scans: u32,
    max_concurrent_scans: u32,
}

impl LocalEngineService {
    pub fn new(version: impl Into<String>, max_concurrent_scans: u32) -> Self {
        Self {
            version: version.into(),
            bind_address: "127.0.0.1".to_string(),
            status: EngineStatus::Stopped,
            active_scans: 0,
            max_concurrent_scans,
        }
    }

    pub fn start(&mut self) -> LocalEngineSnapshot {
        self.status = EngineStatus::Starting;
        self.status = EngineStatus::Ready;
        self.snapshot()
    }

    pub fn stop(&mut self) -> LocalEngineSnapshot {
        self.active_scans = 0;
        self.status = EngineStatus::Stopped;
        self.snapshot()
    }

    pub fn snapshot(&self) -> LocalEngineSnapshot {
        let mut checks = vec![
            EngineHealthCheck {
                component: "scope_validator".to_string(),
                status: EngineComponentStatus::Ready,
                message: "approved target policy loaded".to_string(),
            },
            EngineHealthCheck {
                component: "local_api".to_string(),
                status: match self.status {
                    EngineStatus::Stopped => EngineComponentStatus::Pending,
                    EngineStatus::Starting => EngineComponentStatus::Pending,
                    EngineStatus::Ready => EngineComponentStatus::Ready,
                    EngineStatus::Degraded => EngineComponentStatus::Degraded,
                },
                message: format!("bound to {}", self.bind_address),
            },
            EngineHealthCheck {
                component: "scan_scheduler".to_string(),
                status: if self.active_scans <= self.max_concurrent_scans {
                    EngineComponentStatus::Ready
                } else {
                    EngineComponentStatus::Degraded
                },
                message: format!(
                    "{} of {} scan slots in use",
                    self.active_scans, self.max_concurrent_scans
                ),
            },
        ];

        if self.status == EngineStatus::Stopped {
            checks.push(EngineHealthCheck {
                component: "scan_runtime".to_string(),
                status: EngineComponentStatus::Pending,
                message: "engine is stopped".to_string(),
            });
        }

        LocalEngineSnapshot {
            status: self.status,
            version: self.version.clone(),
            bind_address: self.bind_address.clone(),
            active_scans: self.active_scans,
            max_concurrent_scans: self.max_concurrent_scans,
            checks,
        }
    }
}

impl Default for LocalEngineService {
    fn default() -> Self {
        Self::new(env!("CARGO_PKG_VERSION"), 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_starts_ready_on_loopback() {
        let mut service = LocalEngineService::new("0.1.0", 1);

        let snapshot = service.start();

        assert_eq!(snapshot.status, EngineStatus::Ready);
        assert_eq!(snapshot.bind_address, "127.0.0.1");
        assert!(snapshot
            .checks
            .iter()
            .any(|check| check.component == "scope_validator"
                && check.status == EngineComponentStatus::Ready));
    }

    #[test]
    fn engine_stop_clears_active_runtime() {
        let mut service = LocalEngineService::new("0.1.0", 1);
        service.start();

        let snapshot = service.stop();

        assert_eq!(snapshot.status, EngineStatus::Stopped);
        assert_eq!(snapshot.active_scans, 0);
        assert!(snapshot
            .checks
            .iter()
            .any(|check| check.component == "scan_runtime"
                && check.status == EngineComponentStatus::Pending));
    }
}
