/// Exit node selection constraints (`ExitNodes`/`ExcludeExitNodes`/`StrictNodes`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeSelectionConfig {
    /// Relay nicknames/fingerprints/countries eligible to be used as exits.
    /// Empty means no restriction.
    pub exit_nodes: Vec<String>,
    /// Relay nicknames/fingerprints/countries never used as exits.
    pub exclude_exit_nodes: Vec<String>,
    /// If `true`, `exit_nodes` and other node constraints are treated as
    /// mandatory rather than a preference.
    pub strict_nodes: Option<bool>,
}

impl NodeSelectionConfig {
    /// Sets the eligible exit node list.
    pub fn exit_nodes<I, S>(mut self, nodes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exit_nodes = nodes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the excluded exit node list.
    pub fn exclude_exit_nodes<I, S>(mut self, nodes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_exit_nodes = nodes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets whether node constraints are mandatory rather than a preference.
    pub fn strict_nodes(mut self, value: bool) -> Self {
        self.strict_nodes = Some(value);
        self
    }
}
