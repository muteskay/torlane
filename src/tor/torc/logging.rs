use std::fmt;
use std::path::PathBuf;

/// A Tor log severity level, from most to least verbose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Most verbose: internal diagnostic detail.
    Debug,
    /// Informational messages about normal operation.
    Info,
    /// Notable events that are still part of normal operation.
    Notice,
    /// Problems that do not prevent Tor from working.
    Warn,
    /// Serious problems.
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

/// Where a log line is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDest {
    /// Write to standard output.
    Stdout,
    /// Write to standard error.
    Stderr,
    /// Write to syslog.
    Syslog,
    /// Write to the file at this path.
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

/// One `Log <severity> <destination>` torrc line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// The minimum severity written to this destination.
    pub severity: Severity,
    /// Where matching log lines are written.
    pub destination: LogDest,
}

/// Logging behavior: log destinations, safe logging, and syslog tagging.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoggingConfig {
    /// The configured `Log` lines.
    pub logs: Vec<LogLine>,
    /// If `true`, sensitive values (like addresses) are scrubbed from log
    /// output.
    pub safe_logging: Option<bool>,
    /// A tag appended to Tor's syslog identity, to distinguish multiple Tor
    /// processes in shared syslog output.
    pub syslog_identity_tag: Option<String>,
}

impl LoggingConfig {
    /// Adds a `Log <severity> <destination>` line.
    pub fn log(mut self, severity: Severity, destination: LogDest) -> Self {
        self.logs.push(LogLine {
            severity,
            destination,
        });
        self
    }

    /// Sets whether sensitive values are scrubbed from log output.
    pub fn safe_logging(mut self, value: bool) -> Self {
        self.safe_logging = Some(value);
        self
    }

    /// Sets the syslog identity tag.
    pub fn syslog_identity_tag(mut self, value: impl Into<String>) -> Self {
        self.syslog_identity_tag = Some(value.into());
        self
    }
}
