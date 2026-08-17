use crate::tor::error::TorConfigError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorOption {
    key: String,
    value: String,
}

impl TorOption {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, TorConfigError> {
        let key = key.into();
        let value = value.into();

        if key.is_empty()
            || key
                .chars()
                .any(|c| c.is_whitespace() || c == '\n' || c == '\r' || c == '\0')
        {
            return Err(TorConfigError::InvalidRawOptionKey);
        }

        if value.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
            return Err(TorConfigError::InvalidRawOptionValue);
        }

        Ok(Self { key, value })
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}
