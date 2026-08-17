use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsFormat {
    Prometheus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig {
    pub listen: SocketAddr,
    pub format: MetricsFormat,
    pub policy: Vec<String>,
}

impl MetricsConfig {
    pub fn prometheus(listen: SocketAddr) -> Self {
        Self {
            listen,
            format: MetricsFormat::Prometheus,
            policy: Vec::new(),
        }
    }

    pub fn policy<I, S>(mut self, policy: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.policy = policy.into_iter().map(Into::into).collect();
        self
    }
}
