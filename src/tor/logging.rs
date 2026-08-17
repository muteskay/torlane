use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Debug,
    Info,
    Notice,
    Warn,
    Err,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debug => f.write_str("debug"),
            Self::Info => f.write_str("info"),
            Self::Notice => f.write_str("notice"),
            Self::Warn => f.write_str("warn"),
            Self::Err => f.write_str("err"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDest {
    Stdout,
    Stderr,
    Syslog,
    File(PathBuf),
}

impl fmt::Display for LogDest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => f.write_str("stdout"),
            Self::Stderr => f.write_str("stderr"),
            Self::Syslog => f.write_str("syslog"),
            Self::File(path) => write!(f, "file {}", path.display()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub severity: Severity,
    pub destination: LogDest,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoggingConfig {
    pub logs: Vec<LogLine>,
    pub safe_logging: Option<bool>,
    pub syslog_identity_tag: Option<String>,
}

impl LoggingConfig {
    pub fn log(mut self, severity: Severity, destination: LogDest) -> Self {
        self.logs.push(LogLine {
            severity,
            destination,
        });
        self
    }

    pub fn safe_logging(mut self, value: bool) -> Self {
        self.safe_logging = Some(value);
        self
    }

    pub fn syslog_identity_tag(mut self, value: impl Into<String>) -> Self {
        self.syslog_identity_tag = Some(value.into());
        self
    }
}
