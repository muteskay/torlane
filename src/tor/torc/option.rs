use crate::tor::torc::error::TorConfigError;

/// A single raw `key value` torrc line, for Tor options without a typed API.
///
/// Validated to be injection-safe (no newlines or NUL bytes), but not
/// checked against Tor's actual option grammar or semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorOption {
    key: String,
    value: String,
}

impl TorOption {
    /// Creates a raw option, rejecting keys/values that could inject
    /// additional torrc lines or otherwise corrupt the rendered config.
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

    /// The option's torrc key, e.g. `"DormantTimeoutEnabled"`.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The option's torrc value, e.g. `"0"`.
    pub fn value(&self) -> &str {
        &self.value
    }
}
