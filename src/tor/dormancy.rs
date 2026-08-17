#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DormancyConfig {
    pub timeout_enabled: Option<bool>,
    pub on_first_startup: Option<bool>,
    pub canceled_by_startup: Option<bool>,
}

impl DormancyConfig {
    pub fn tor_default() -> Self {
        Self::default()
    }

    pub fn always_ready() -> Self {
        Self {
            timeout_enabled: Some(false),
            on_first_startup: Some(false),
            canceled_by_startup: None,
        }
    }

    pub fn timeout_enabled(mut self, value: bool) -> Self {
        self.timeout_enabled = Some(value);
        self
    }

    pub fn on_first_startup(mut self, value: bool) -> Self {
        self.on_first_startup = Some(value);
        self
    }

    pub fn canceled_by_startup(mut self, value: bool) -> Self {
        self.canceled_by_startup = Some(value);
        self
    }
}
