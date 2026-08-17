#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemConfig {
    pub avoid_disk_writes: Option<bool>,
    pub hardware_accel: Option<bool>,
    pub conn_limit: Option<u32>,
    pub disable_debugger_attachment: Option<bool>,
}

impl SystemConfig {
    pub fn avoid_disk_writes(mut self, value: bool) -> Self {
        self.avoid_disk_writes = Some(value);
        self
    }

    pub fn hardware_accel(mut self, value: bool) -> Self {
        self.hardware_accel = Some(value);
        self
    }

    pub fn conn_limit(mut self, value: u32) -> Self {
        self.conn_limit = Some(value);
        self
    }

    pub fn disable_debugger_attachment(mut self, value: bool) -> Self {
        self.disable_debugger_attachment = Some(value);
        self
    }
}
