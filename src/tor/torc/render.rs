use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::tor::torc::bridges::{Bridge, BridgeConfig};
use crate::tor::torc::config::TorConfig;
use crate::tor::torc::control::{ControlAuth, ControlListen};
use crate::tor::torc::logging::{LogDest, LoggingConfig};
use crate::tor::torc::socks::SocksPort;
use crate::tor::torc::value::{Flag, PortSpec};

pub fn render_config(config: &TorConfig) -> String {
    let mut out = String::new();

    section(
        &mut out,
        "Directories",
        vec![format!("DataDirectory {}", config.data_directory.display())],
    );

    let mut control = Vec::new();
    if let Some(control_config) = &config.control {
        control.push(render_control_port(&control_config.listen));
        match &control_config.auth {
            ControlAuth::Cookie => control.push("CookieAuthentication 1".to_string()),
            ControlAuth::HashedPassword(hash) => {
                control.push(format!("HashedControlPassword {hash}"));
            }
            ControlAuth::None => control.push("CookieAuthentication 0".to_string()),
        }
        if let Some(path) = &control_config.write_port_to_file {
            control.push(format!("ControlPortWriteToFile {}", path.display()));
        }
        if let Some(pid) = control_config.owning_controller_process {
            control.push(format!("__OwningControllerProcess {pid}"));
        }
    }
    section(&mut out, "Control interface", control);

    section(
        &mut out,
        "SOCKS listeners",
        config
            .socks
            .listeners()
            .iter()
            .map(render_socks_port)
            .collect(),
    );

    section(
        &mut out,
        "Address family",
        present([
            config
                .network
                .client_use_ipv4
                .map(|v| format!("ClientUseIPv4 {}", Flag(v))),
            config
                .network
                .client_use_ipv6
                .map(|v| format!("ClientUseIPv6 {}", Flag(v))),
        ]),
    );

    section(
        &mut out,
        "Circuits and timeouts",
        present([
            duration_line("MaxCircuitDirtiness", config.circuits.max_circuit_dirtiness),
            duration_line("NewCircuitPeriod", config.circuits.new_circuit_period),
            duration_line(
                "CircuitsAvailableTimeout",
                config.circuits.circuits_available_timeout,
            ),
            duration_line("SocksTimeout", config.circuits.socks_timeout),
            duration_line("CircuitBuildTimeout", config.circuits.circuit_build_timeout),
            config
                .circuits
                .learn_circuit_build_timeout
                .map(|v| format!("LearnCircuitBuildTimeout {}", Flag(v))),
            duration_line(
                "CircuitStreamTimeout",
                config.circuits.circuit_stream_timeout,
            ),
            config
                .circuits
                .max_client_circuits_pending
                .map(|v| format!("MaxClientCircuitsPending {v}")),
            config
                .circuits
                .num_entry_guards
                .map(|v| format!("NumEntryGuards {v}")),
            config
                .circuits
                .use_entry_guards
                .map(|v| format!("UseEntryGuards {}", Flag(v))),
        ]),
    );

    section(
        &mut out,
        "Traffic analysis resistance",
        present([
            config
                .padding
                .connection_padding
                .map(|v| format!("ConnectionPadding {v}")),
            config
                .padding
                .reduced_connection_padding
                .map(|v| format!("ReducedConnectionPadding {}", Flag(v))),
            config
                .padding
                .circuit_padding
                .map(|v| format!("CircuitPadding {}", Flag(v))),
            config
                .padding
                .reduced_circuit_padding
                .map(|v| format!("ReducedCircuitPadding {}", Flag(v))),
            duration_line("KeepalivePeriod", config.padding.keepalive_period),
        ]),
    );

    if let Some(bridges) = &config.bridges {
        section(&mut out, "Bridges", render_bridges(bridges));
    }

    section(
        &mut out,
        "Node selection",
        present([
            non_empty_list("ExitNodes", &config.node_selection.exit_nodes),
            non_empty_list(
                "ExcludeExitNodes",
                &config.node_selection.exclude_exit_nodes,
            ),
            config
                .node_selection
                .strict_nodes
                .map(|v| format!("StrictNodes {}", Flag(v))),
        ]),
    );

    section(
        &mut out,
        "System",
        present([
            config
                .system
                .avoid_disk_writes
                .map(|v| format!("AvoidDiskWrites {}", Flag(v))),
            config
                .system
                .hardware_accel
                .map(|v| format!("HardwareAccel {}", Flag(v))),
            config.system.conn_limit.map(|v| format!("ConnLimit {v}")),
            config
                .system
                .disable_debugger_attachment
                .map(|v| format!("DisableDebuggerAttachment {}", Flag(v))),
        ]),
    );

    section(&mut out, "Logging", render_logging(&config.logging));

    section(
        &mut out,
        "Raw",
        config
            .raw_options
            .iter()
            .map(|option| format!("{} {}", option.key(), option.value()))
            .collect(),
    );

    out
}

fn section(out: &mut String, name: &str, lines: Vec<String>) {
    if lines.is_empty() {
        return;
    }

    if !out.is_empty() {
        out.push('\n');
    }

    out.push_str(&format!("# *** {name} ***\n"));
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
}

fn present<const N: usize>(items: [Option<String>; N]) -> Vec<String> {
    items.into_iter().flatten().collect()
}

fn duration_line(name: &str, value: Option<Duration>) -> Option<String> {
    value.map(|duration| format!("{name} {}", duration.as_secs()))
}

fn non_empty_list(name: &str, values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| format!("{name} {}", values.join(",")))
}

fn render_control_port(listen: &ControlListen) -> String {
    match listen {
        ControlListen::Tcp { addr, port } => {
            format!("ControlPort {}", render_addr_port(*addr, port))
        }
        ControlListen::Unix(path) => format!("ControlPort unix:{}", path.display()),
    }
}

fn render_socks_port(listener: &SocksPort) -> String {
    let mut parts = vec![format!(
        "SocksPort {}",
        render_addr_port(listener.addr, &listener.port)
    )];
    parts.extend(listener.flags.iter().map(ToString::to_string));
    parts.extend(listener.isolation.iter().map(ToString::to_string));
    parts.join(" ")
}

fn render_addr_port(addr: IpAddr, port: &PortSpec) -> String {
    match port {
        PortSpec::Num(port) => SocketAddr::new(addr, *port).to_string(),
        PortSpec::Auto => format!("{addr}:auto"),
        PortSpec::Unix(path) => format!("unix:{}", path.display()),
    }
}

fn render_bridges(bridges: &BridgeConfig) -> Vec<String> {
    let mut lines = vec![format!("UseBridges {}", Flag(bridges.use_bridges))];

    for plugin in &bridges.transport_plugins {
        let mut line = format!(
            "ClientTransportPlugin {} exec {}",
            plugin.names.join(","),
            plugin.executable.display()
        );
        for arg in &plugin.args {
            line.push(' ');
            line.push_str(arg);
        }
        lines.push(line);
    }

    lines.extend(bridges.bridges.iter().map(render_bridge));
    lines
}

fn render_bridge(bridge: &Bridge) -> String {
    let mut parts = vec!["Bridge".to_string()];
    if let Some(transport) = &bridge.transport {
        parts.push(transport.clone());
    }
    parts.push(bridge.addr.to_string());
    if let Some(fingerprint) = &bridge.fingerprint {
        parts.push(fingerprint.clone());
    }
    parts.extend(
        bridge
            .args
            .iter()
            .map(|(key, value)| format!("{key}={value}")),
    );
    parts.join(" ")
}

fn render_logging(logging: &LoggingConfig) -> Vec<String> {
    let mut lines = Vec::new();

    for log in &logging.logs {
        lines.push(format!("Log {} {}", log.severity, log.destination));
    }

    if let Some(value) = logging.safe_logging {
        lines.push(format!("SafeLogging {}", Flag(value)));
    }

    if let Some(tag) = &logging.syslog_identity_tag {
        lines.push(format!("SyslogIdentityTag {tag}"));
    }

    lines
}

#[allow(dead_code)]
fn _log_dest_keeps_import_used(_: &LogDest) {}
