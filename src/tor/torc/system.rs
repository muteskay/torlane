/// System-level resource behavior (disk, hardware acceleration, connection
/// limits, debugger attachment).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemConfig {
    /// If `true`, Tor avoids writing to disk when possible.
    pub avoid_disk_writes: Option<bool>,
    /// If `true`, enables hardware-accelerated cryptography where available.
    pub hardware_accel: Option<bool>,
    /// The maximum number of file descriptors/connections Tor may use.
    pub conn_limit: Option<u32>,
    /// If `true`, prevents other processes from attaching a debugger to Tor.
    pub disable_debugger_attachment: Option<bool>,
}

impl SystemConfig {
    /// Sets whether Tor avoids writing to disk when possible.
    pub fn avoid_disk_writes(mut self, value: bool) -> Self {
        self.avoid_disk_writes = Some(value);
        self
    }

    /// Sets whether hardware-accelerated cryptography is enabled.
    pub fn hardware_accel(mut self, value: bool) -> Self {
        self.hardware_accel = Some(value);
        self
    }

    /// Sets the maximum number of file descriptors/connections.
    pub fn conn_limit(mut self, value: u32) -> Self {
        self.conn_limit = Some(value);
        self
    }

    /// Sets whether debugger attachment is disabled.
    pub fn disable_debugger_attachment(mut self, value: bool) -> Self {
        self.disable_debugger_attachment = Some(value);
        self
    }
}
