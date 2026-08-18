use crate::tor::instance::layout::InstanceLayout;
use crate::tor::instance::policy::TorPolicy;
use crate::tor::torc::{ControlConfig, SocksConfig, TorConfig, TorConfigBuilder, TorConfigError};

pub fn build_runtime_config(
    policy: &TorPolicy,
    layout: &InstanceLayout,
    parent_pid: u32,
) -> Result<TorConfig, TorConfigError> {
    let mut builder = TorConfigBuilder::new(&layout.data_dir)
        .network(policy.network.clone())
        .circuits(policy.circuits.clone())
        .padding(policy.padding.clone())
        .node_selection(policy.node_selection.clone())
        .system(policy.system.clone())
        .logging(policy.logging.clone())
        .socks(SocksConfig::isolated_auth_auto())
        .control(
            ControlConfig::auto_tcp()
                .cookie_authentication()
                .write_port_to_file(&layout.control_port_file)
                .owning_controller_process(parent_pid),
        );

    if let Some(bridges) = &policy.bridges {
        builder = builder.bridges(bridges.clone());
    }

    if let Some(metrics) = &policy.metrics {
        builder = builder.metrics(metrics.clone());
    }

    builder.build()
}
