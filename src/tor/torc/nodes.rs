#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeSelectionConfig {
    pub exit_nodes: Vec<String>,
    pub exclude_exit_nodes: Vec<String>,
    pub strict_nodes: Option<bool>,
}

impl NodeSelectionConfig {
    pub fn exit_nodes<I, S>(mut self, nodes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exit_nodes = nodes.into_iter().map(Into::into).collect();
        self
    }

    pub fn exclude_exit_nodes<I, S>(mut self, nodes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_exit_nodes = nodes.into_iter().map(Into::into).collect();
        self
    }

    pub fn strict_nodes(mut self, value: bool) -> Self {
        self.strict_nodes = Some(value);
        self
    }
}
