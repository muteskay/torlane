use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use torlane::*;

#[test]
fn value_types_render_exactly() {
    assert_eq!(Flag(true).to_string(), "1");
    assert_eq!(Flag(false).to_string(), "0");
    assert_eq!(Tristate::Off.to_string(), "0");
    assert_eq!(Tristate::On.to_string(), "1");
    assert_eq!(Tristate::Auto.to_string(), "auto");
    assert_eq!(PortSpec::Num(9050).to_string(), "9050");
    assert_eq!(PortSpec::Auto.to_string(), "auto");
    assert_eq!(Isolation::IsolateSocksAuth.to_string(), "IsolateSOCKSAuth");
    assert_eq!(
        Isolation::KeepAliveIsolateSocksAuth.to_string(),
        "KeepAliveIsolateSOCKSAuth"
    );
    assert_eq!(SocksFlag::ExtendedErrors.to_string(), "ExtendedErrors");
    assert_eq!(Severity::Notice.to_string(), "notice");
    assert_eq!(LogDest::Stdout.to_string(), "stdout");
}

#[test]
fn localhost_control_port_renders_cookie_auth() {
    let config = TorConfigBuilder::new("/tmp/tor/data")
        .control(
            ControlConfig::tcp(20000)
                .bind_localhost()
                .cookie_authentication()
                .owning_controller_process(12345),
        )
        .build()
        .unwrap();

    assert_eq!(
        config.render(),
        "# *** Directories ***\n\
DataDirectory /tmp/tor/data\n\
\n\
# *** Control interface ***\n\
ControlPort 127.0.0.1:20000\n\
CookieAuthentication 1\n\
__OwningControllerProcess 12345\n"
    );
}

#[test]
fn control_port_variants_render() {
    let ipv6 = TorConfigBuilder::new("/tmp/tor/data")
        .control(ControlConfig::tcp(20000).bind(IpAddr::V6(Ipv6Addr::LOCALHOST)))
        .build()
        .unwrap();
    assert!(ipv6.render().contains("ControlPort [::1]:20000\n"));

    let unix = TorConfigBuilder::new("/tmp/tor/data")
        .control(ControlConfig::unix("/tmp/tor/control.sock"))
        .build()
        .unwrap();
    assert!(
        unix.render()
            .contains("ControlPort unix:/tmp/tor/control.sock\n")
    );

    let auto = TorConfigBuilder::new("/tmp/tor/data")
        .control(ControlConfig::auto_tcp().write_port_to_file("/tmp/tor/control.port"))
        .build()
        .unwrap();
    assert!(auto.render().contains("ControlPort 127.0.0.1:auto\n"));
    assert!(
        auto.render()
            .contains("ControlPortWriteToFile /tmp/tor/control.port\n")
    );
}

#[test]
fn control_port_auth_validation_and_warnings() {
    let unsafe_control = ControlConfig::tcp(20000)
        .bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .no_authentication();
    let error = TorConfigBuilder::new("/tmp/tor/data")
        .control(unsafe_control)
        .build()
        .unwrap_err();
    assert_eq!(error, TorConfigError::UnauthenticatedNonLoopbackControlPort);

    let loopback = TorConfigBuilder::new("/tmp/tor/data")
        .control(ControlConfig::tcp(20000).no_authentication())
        .build()
        .unwrap();
    assert_eq!(
        loopback.warnings(),
        &[TorConfigWarning::UnauthenticatedLoopbackControlPort]
    );

    let auto = TorConfigBuilder::new("/tmp/tor/data")
        .control(ControlConfig::auto_tcp())
        .build()
        .unwrap();
    assert_eq!(
        auto.warnings(),
        &[TorConfigWarning::AutoControlPortWithoutWriteFile]
    );
}

#[test]
fn socks_isolated_auth_renders_one_listener() {
    let config = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::isolated_auth(20300))
        .build()
        .unwrap();

    assert_eq!(config.socks().listeners().len(), 1);
    assert!(config.render().contains(
        "SocksPort 127.0.0.1:20300 ExtendedErrors IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth\n"
    ));
}

#[test]
fn socks_port_range_validates_count_and_overflow() {
    let range = SocksConfig::port_range(20300, 64);
    assert_eq!(range.listeners().len(), 64);

    let error = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::port_range(20300, 0))
        .build()
        .unwrap_err();
    assert_eq!(error, TorConfigError::EmptySocksPortRange);

    let error = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::port_range(65535, 2))
        .build()
        .unwrap_err();
    assert_eq!(error, TorConfigError::PortRangeOverflow);
}

#[test]
fn duplicate_listener_ports_are_rejected() {
    let error = TorConfigBuilder::new("/tmp/tor/data")
        .control(ControlConfig::tcp(20300))
        .socks(SocksConfig::isolated_auth(20300))
        .build()
        .unwrap_err();
    assert_eq!(error, TorConfigError::DuplicatePort(20300));
}

#[test]
fn identity_pool_generates_unique_runtime_credentials() {
    let addr: SocketAddr = "127.0.0.1:20300".parse().unwrap();
    let pool = TorIdentityPool::generate(addr, 64).unwrap();

    assert_eq!(pool.identity_count(), 64);
    let usernames: HashSet<_> = pool
        .identities()
        .iter()
        .map(|identity| identity.auth.username.as_str())
        .collect();
    let passwords: HashSet<_> = pool
        .identities()
        .iter()
        .map(|identity| identity.auth.password.as_str())
        .collect();

    assert_eq!(usernames.len(), 64);
    assert_eq!(passwords.len(), 64);

    for (index, identity) in pool.identities().iter().enumerate() {
        assert_eq!(identity.id, index as u64);
        assert_eq!(identity.proxy_addr, addr);
        assert_eq!(identity.auth.username, format!("worker-{index:06}"));
        assert!(!identity.auth.password.is_empty());
        assert_ne!(identity.auth.password, identity.auth.username);
    }
}

#[test]
fn bridge_validation_covers_obfs4() {
    let bridge_addr: SocketAddr = "192.0.2.10:443".parse().unwrap();
    let valid = BridgeConfig::obfs4("/usr/bin/lyrebird").bridge(Obfs4Bridge::new(
        bridge_addr,
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "abc",
        0,
    ));

    let config = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::isolated_auth(20300))
        .bridges(valid)
        .build()
        .unwrap();
    assert!(
        config
            .render()
            .contains("ClientTransportPlugin obfs4 exec /usr/bin/lyrebird\n")
    );
    assert!(config.render().contains("Bridge obfs4 192.0.2.10:443"));

    let error = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::isolated_auth(20300))
        .bridges(BridgeConfig::obfs4("/usr/bin/lyrebird"))
        .build()
        .unwrap_err();
    assert_eq!(error, TorConfigError::BridgesEnabledButNoneConfigured);

    let error = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::isolated_auth(20300))
        .bridges(BridgeConfig::new().bridge(Bridge::new(bridge_addr).transport("obfs4")))
        .build()
        .unwrap_err();
    assert_eq!(
        error,
        TorConfigError::MissingTransportPlugin("obfs4".to_string())
    );

    let error = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::isolated_auth(20300))
        .bridges(
            BridgeConfig::obfs4("/usr/bin/lyrebird").bridge(Obfs4Bridge::new(
                bridge_addr,
                "",
                "abc",
                0,
            )),
        )
        .build()
        .unwrap_err();
    assert_eq!(
        error,
        TorConfigError::InvalidObfs4Bridge("empty fingerprint")
    );
}

#[test]
fn raw_options_are_injection_safe() {
    assert_eq!(
        TorOption::new("Foo\nSocksPort", "9050").unwrap_err(),
        TorConfigError::InvalidRawOptionKey
    );
    assert_eq!(
        TorOption::new("Foo", "bar\nControlPort 0.0.0.0:1234").unwrap_err(),
        TorConfigError::InvalidRawOptionValue
    );
    assert_eq!(
        TorOption::new("Foo Bar", "1").unwrap_err(),
        TorConfigError::InvalidRawOptionKey
    );
    assert!(TorOption::new("SomeFutureOption", "123").is_ok());
}

#[test]
fn standard_scraper_snapshot() {
    let config = TorConfigBuilder::scraper("/tmp/tor/tor_0/data")
        .control(
            ControlConfig::tcp(20000)
                .cookie_authentication()
                .owning_controller_process(12345),
        )
        .socks(SocksConfig::isolated_auth(20300))
        .logging(LoggingConfig::default().log(Severity::Notice, LogDest::Stdout))
        .build()
        .unwrap();

    assert_eq!(
        config.render(),
        "# *** Directories ***\n\
DataDirectory /tmp/tor/tor_0/data\n\
\n\
# *** Control interface ***\n\
ControlPort 127.0.0.1:20000\n\
CookieAuthentication 1\n\
__OwningControllerProcess 12345\n\
\n\
# *** SOCKS listeners ***\n\
SocksPort 127.0.0.1:20300 ExtendedErrors IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth\n\
\n\
# *** Dormant mode ***\n\
DormantTimeoutEnabled 0\n\
DormantOnFirstStartup 0\n\
\n\
# *** System ***\n\
AvoidDiskWrites 1\n\
\n\
# *** Logging ***\n\
Log notice stdout\n"
    );
}

#[test]
fn comprehensive_config_writes_rendered_torrc_file() {
    let root = std::env::temp_dir().join(format!(
        "torlane-comprehensive-test-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    let data_dir = root.join("data");
    let torrc = root.join("torrc");
    let control_port_file = root.join("control.port");
    let tor_log = root.join("logs").join("tor.log");
    let bridge_addr: SocketAddr = "192.0.2.20:443".parse().unwrap();
    let metrics_addr: SocketAddr = "127.0.0.1:9035".parse().unwrap();

    let config = TorConfigBuilder::new(&data_dir)
        .control(
            ControlConfig::auto_tcp()
                .hashed_password("16:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
                .write_port_to_file(&control_port_file)
                .owning_controller_process(4242),
        )
        .socks(
            SocksConfig::new().listener(
                SocksPort::localhost(20300)
                    .with_flag(SocksFlag::ExtendedErrors)
                    .with_flag(SocksFlag::PreferIPv6)
                    .with_isolation(Isolation::IsolateSocksAuth)
                    .with_isolation(Isolation::KeepAliveIsolateSocksAuth)
                    .with_isolation(Isolation::SessionGroup(7)),
            ),
        )
        .network(NetworkConfig::dual_stack())
        .circuits(
            CircuitConfig::default()
                .max_dirtiness(Duration::from_secs(600))
                .new_circuit_period(Duration::from_secs(45))
                .circuits_available_timeout(Duration::from_secs(30))
                .socks_timeout(Duration::from_secs(120))
                .circuit_build_timeout(Duration::from_secs(60))
                .learn_circuit_build_timeout(false)
                .circuit_stream_timeout(Duration::from_secs(90))
                .max_client_circuits_pending(64)
                .num_entry_guards(3)
                .use_entry_guards(true),
        )
        .padding(
            PaddingConfig::default()
                .connection_padding(Tristate::Auto)
                .reduced_connection_padding(false)
                .circuit_padding(true)
                .reduced_circuit_padding(false)
                .keepalive_period(Duration::from_secs(300)),
        )
        .dormancy(
            DormancyConfig::default()
                .timeout_enabled(false)
                .on_first_startup(false)
                .canceled_by_startup(true),
        )
        .bridges(
            BridgeConfig::obfs4("/usr/bin/lyrebird").bridge(Obfs4Bridge::new(
                bridge_addr,
                "0123456789ABCDEF0123456789ABCDEF01234567",
                "abc",
                1,
            )),
        )
        .node_selection(
            NodeSelectionConfig::default()
                .exit_nodes(["{us}", "{de}"])
                .exclude_exit_nodes(["{ru}"])
                .strict_nodes(true),
        )
        .system(
            SystemConfig::default()
                .avoid_disk_writes(true)
                .hardware_accel(true)
                .conn_limit(4096)
                .disable_debugger_attachment(true),
        )
        .logging(
            LoggingConfig::default()
                .log(Severity::Notice, LogDest::Stdout)
                .log(Severity::Warn, LogDest::File(tor_log.clone()))
                .safe_logging(true)
                .syslog_identity_tag("torlane-test"),
        )
        .metrics(MetricsConfig::prometheus(metrics_addr).policy(["accept 127.0.0.1"]))
        .raw_option(TorOption::new("UseMicrodescriptors", "1").unwrap())
        .build()
        .unwrap();

    config.write_to_sync(&torrc).unwrap();

    let saved = fs::read_to_string(&torrc).unwrap();
    assert_eq!(saved, config.render());
    assert!(saved.contains(&format!("DataDirectory {}\n", data_dir.display())));
    assert!(saved.contains("ControlPort 127.0.0.1:auto\n"));
    assert!(saved.contains(&format!(
        "ControlPortWriteToFile {}\n",
        control_port_file.display()
    )));
    assert!(saved.contains(
        "SocksPort 127.0.0.1:20300 ExtendedErrors PreferIPv6 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth SessionGroup=7\n"
    ));
    assert!(saved.contains("ClientUseIPv4 1\n"));
    assert!(saved.contains("MaxCircuitDirtiness 600\n"));
    assert!(saved.contains("ConnectionPadding auto\n"));
    assert!(saved.contains("DormantCanceledByStartup 1\n"));
    assert!(saved.contains(
        "Bridge obfs4 192.0.2.20:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=1\n"
    ));
    assert!(saved.contains("ExitNodes {us},{de}\n"));
    assert!(saved.contains("AvoidDiskWrites 1\n"));
    assert!(saved.contains(&format!("Log warn file {}\n", tor_log.display())));
    assert!(saved.contains("MetricsPortPolicy accept 127.0.0.1\n"));
    assert!(saved.contains("UseMicrodescriptors 1\n"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn advanced_circuit_and_metrics_render() {
    let metrics_addr: SocketAddr = "127.0.0.1:9035".parse().unwrap();
    let config = TorConfigBuilder::new("/tmp/tor/data")
        .socks(SocksConfig::isolated_auth(20300))
        .circuits(
            CircuitConfig::default()
                .max_dirtiness(Duration::from_secs(600))
                .max_client_circuits_pending(64),
        )
        .metrics(MetricsConfig::prometheus(metrics_addr))
        .raw_option(TorOption::new("SomeFutureOption", "123").unwrap())
        .build()
        .unwrap();

    let rendered = config.render();
    assert!(rendered.contains("MaxCircuitDirtiness 600\n"));
    assert!(rendered.contains("MaxClientCircuitsPending 64\n"));
    assert!(rendered.contains("MetricsPort 127.0.0.1:9035\n"));
    assert!(rendered.contains("SomeFutureOption 123\n"));
}

#[cfg(unix)]
#[test]
fn atomic_write_uses_private_unix_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!(
        "torlane-permissions-{}-{}.torrc",
        std::process::id(),
        unique_nanos()
    ));
    let data_dir = std::env::temp_dir().join(format!(
        "torlane-permissions-data-{}-{}",
        std::process::id(),
        unique_nanos()
    ));

    let config = TorConfigBuilder::new(data_dir)
        .socks(SocksConfig::isolated_auth(20300))
        .build()
        .unwrap();
    config.write_to_sync(&path).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let _ = fs::remove_file(path);
}

#[test]
fn generated_config_passes_tor_verify() {
    let tor_binary = std::env::var("TOR_BINARY").unwrap_or_else(|_| "tor".to_string());
    let root = std::env::temp_dir().join(format!(
        "torlane-verify-test-{}-{}",
        std::process::id(),
        unique_nanos()
    ));
    let data_dir = root.join("data");
    let torrc = root.join("torrc");
    fs::create_dir_all(&root).unwrap();

    let config = TorConfigBuilder::scraper(&data_dir)
        .control(
            ControlConfig::auto_tcp()
                .cookie_authentication()
                .write_port_to_file(root.join("control.port")),
        )
        .socks(SocksConfig::isolated_auth(20300))
        .logging(LoggingConfig::default().log(Severity::Notice, LogDest::Stdout))
        .build()
        .unwrap();
    config.write_to_sync(&torrc).unwrap();

    let output = std::process::Command::new(tor_binary)
        .arg("-f")
        .arg(&torrc)
        .arg("--verify-config")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(root);
}

fn unique_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}
