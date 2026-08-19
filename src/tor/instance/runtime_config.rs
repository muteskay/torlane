use crate::tor::instance::layout::InstanceLayout;
use crate::tor::instance::policy::TorPolicy;
use crate::tor::torc::{ControlConfig, SocksConfig, TorConfig, TorConfigBuilder, TorConfigError};

pub fn build_runtime_config(
    policy: &TorPolicy,
    layout: &InstanceLayout,
    parent_pid: u32,
) -> Result<TorConfig, TorConfigError> {
    let mut builder = TorConfigBuilder::new(&layout.data_dir)
        .network(policy.network().clone())
        .circuits(policy.circuits().clone())
        .padding(policy.padding().clone())
        .node_selection(policy.node_selection().clone())
        .system(policy.system().clone())
        .logging(policy.logging().clone())
        .socks(SocksConfig::isolated_auth_auto())
        .control(
            ControlConfig::auto_tcp()
                .cookie_authentication()
                .write_port_to_file(&layout.control_port_file)
                .owning_controller_process(parent_pid),
        );

    if let Some(bridges) = policy.bridges() {
        builder = builder.bridges(bridges.clone());
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use crate::tor::torc::{LogDest, LoggingConfig, NetworkConfig, Severity, SystemConfig};

    use super::*;

    fn unique_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    }

    fn count_rendered_options(rendered: &str, option: &str) -> usize {
        let prefix = format!("{option} ");
        rendered
            .lines()
            .filter(|line| line.starts_with(&prefix))
            .count()
    }

    #[test]
    fn runtime_config_owns_pool_topology() {
        let root = std::env::temp_dir().join(format!(
            "torlane-runtime-config-{}-{}",
            std::process::id(),
            unique_nanos()
        ));
        let layout = InstanceLayout::prepare(&root).unwrap();
        let policy = TorPolicy::default()
            .with_network(NetworkConfig::dual_stack())
            .with_logging(LoggingConfig::default().log(Severity::Notice, LogDest::Stdout))
            .with_system(SystemConfig::default().avoid_disk_writes(true));

        let config = build_runtime_config(&policy, &layout, 4242).unwrap();
        let rendered = config.render();

        assert_eq!(count_rendered_options(&rendered, "SocksPort"), 1);
        assert!(rendered.contains("SocksPort 127.0.0.1:auto "));
        assert!(rendered.contains("ExtendedErrors"));
        assert!(rendered.contains("IsolateSOCKSAuth"));
        assert!(rendered.contains("KeepAliveIsolateSOCKSAuth"));
        assert_eq!(count_rendered_options(&rendered, "ControlPort"), 1);
        assert!(rendered.contains("ControlPort 127.0.0.1:auto\n"));
        assert!(rendered.contains(&format!(
            "ControlPortWriteToFile {}\n",
            layout.control_port_file.display()
        )));
        assert!(rendered.contains("CookieAuthentication 1\n"));
        assert!(rendered.contains("__OwningControllerProcess 4242\n"));
        assert!(rendered.contains(&format!("DataDirectory {}\n", layout.data_dir.display())));
        assert!(rendered.contains("ClientUseIPv6 1\n"));
        assert!(rendered.contains("AvoidDiskWrites 1\n"));
        assert!(rendered.contains("Log notice stdout\n"));
        assert!(!rendered.contains("/tmp/tor/data"));
        assert!(!rendered.contains("127.0.0.1:20300"));
        assert!(!root.join("torrc").exists());

        let _ = std::fs::remove_dir_all(root);
    }
}
