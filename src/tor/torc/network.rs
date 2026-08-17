#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkConfig {
    pub client_use_ipv4: Option<bool>,
    pub client_use_ipv6: Option<bool>,
}

impl NetworkConfig {
    pub fn tor_default() -> Self {
        Self::default()
    }

    pub fn ipv4_only() -> Self {
        Self {
            client_use_ipv4: Some(true),
            client_use_ipv6: Some(false),
        }
    }

    pub fn dual_stack() -> Self {
        Self {
            client_use_ipv4: Some(true),
            client_use_ipv6: Some(true),
        }
    }
}
