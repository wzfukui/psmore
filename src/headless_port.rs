use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    cli::PortProtocol,
    model::{ProcessInfo, process_command_line, process_path, sanitize_terminal_text},
    network::{NetworkEndpoint, NetworkScope, scan_network},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const PORT_SCHEMA: &str = "psmore.port-inspection";
const PORT_SCHEMA_VERSION: u32 = 1;

pub(crate) struct CapturedPort {
    port: u16,
    protocol: PortProtocol,
    scope: NetworkScope,
    generated_at_unix_ms: u64,
    system_process_count: usize,
    processes: HashMap<Pid, ProcessInfo>,
    endpoints: Vec<NetworkEndpoint>,
    warning: Option<String>,
}

impl CapturedPort {
    pub(crate) fn matched_endpoint_count(&self) -> usize {
        self.endpoints.len()
    }
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    endpoint
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
}

fn protocol_matches(protocol: PortProtocol, endpoint: &NetworkEndpoint) -> bool {
    match protocol {
        PortProtocol::Any => matches!(endpoint.protocol.as_str(), "TCP" | "UDP"),
        PortProtocol::Tcp => endpoint.protocol == "TCP",
        PortProtocol::Udp => endpoint.protocol == "UDP",
    }
}

fn matching_endpoints(
    endpoints: &[NetworkEndpoint],
    port: u16,
    protocol: PortProtocol,
    scope: NetworkScope,
) -> Vec<NetworkEndpoint> {
    endpoints
        .iter()
        .filter(|endpoint| scope.includes(endpoint))
        .filter(|endpoint| protocol_matches(protocol, endpoint))
        .filter(|endpoint| endpoint_port(&endpoint.local_endpoint) == Some(port))
        .cloned()
        .collect()
}

pub(crate) fn capture_port(port: u16, protocol: PortProtocol, all: bool) -> CapturedPort {
    let mut provider = NativeProcessProvider::new();
    let processes: HashMap<Pid, ProcessInfo> = provider
        .refresh()
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let scan = scan_network(&processes);
    let scope = if all {
        NetworkScope::All
    } else {
        NetworkScope::Listeners
    };
    let endpoints = matching_endpoints(&scan.endpoints, port, protocol, scope);
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    CapturedPort {
        port,
        protocol,
        scope,
        generated_at_unix_ms,
        system_process_count: processes
            .len()
            .saturating_sub(usize::from(processes.contains_key(&Pid::from_u32(0)))),
        processes,
        endpoints,
        warning: scan.warning,
    }
}

#[derive(Debug, Serialize)]
struct JsonPortInspection<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    local_port: u16,
    protocol: &'static str,
    scope: &'static str,
    system_process_count: usize,
    matched_endpoint_count: usize,
    known_owner_count: usize,
    unresolved_endpoint_count: usize,
    policy: Option<JsonPolicy<'a>>,
    warning: Option<&'a str>,
    endpoints: Vec<JsonEndpoint>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonPolicy<'a> {
    expectation: &'a str,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct JsonEndpoint {
    protocol: String,
    local_endpoint: String,
    remote_endpoint: String,
    state: String,
    pid: Option<u32>,
    fd: String,
    process: String,
    user: Option<String>,
    path: Option<String>,
    command: Option<String>,
    namespace: Option<String>,
}

fn json_endpoint(
    endpoint: &NetworkEndpoint,
    processes: &HashMap<Pid, ProcessInfo>,
) -> JsonEndpoint {
    let process = endpoint.pid.and_then(|pid| processes.get(&pid));
    JsonEndpoint {
        protocol: endpoint.protocol.clone(),
        local_endpoint: endpoint.local_endpoint.clone(),
        remote_endpoint: endpoint.remote_endpoint.clone(),
        state: endpoint.state.clone(),
        pid: endpoint.pid.map(Pid::as_u32),
        fd: endpoint.fd.clone(),
        process: endpoint.process.clone(),
        user: process.map(|process| process.user.clone()),
        path: process.map(process_path),
        command: process.map(process_command_line),
        namespace: (!endpoint.namespace.is_empty()).then(|| endpoint.namespace.clone()),
    }
}

fn known_owner_count(endpoints: &[NetworkEndpoint]) -> usize {
    endpoints
        .iter()
        .filter_map(|endpoint| endpoint.pid)
        .collect::<HashSet<_>>()
        .len()
}

fn scope_key(scope: NetworkScope) -> &'static str {
    match scope {
        NetworkScope::Listeners => "listeners",
        NetworkScope::All => "all",
    }
}

pub(crate) fn render_port_json(
    captured: &CapturedPort,
    expectation: Option<&str>,
    passed: Option<bool>,
) -> Result<String, String> {
    let policy = expectation
        .zip(passed)
        .map(|(expectation, passed)| JsonPolicy {
            expectation,
            passed,
        });
    serde_json::to_string_pretty(&JsonPortInspection {
        schema: PORT_SCHEMA,
        schema_version: PORT_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, user, socket, and namespace information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        local_port: captured.port,
        protocol: captured.protocol.label(),
        scope: scope_key(captured.scope),
        system_process_count: captured.system_process_count,
        matched_endpoint_count: captured.endpoints.len(),
        known_owner_count: known_owner_count(&captured.endpoints),
        unresolved_endpoint_count: captured
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.pid.is_none())
            .count(),
        policy,
        warning: captured.warning.as_deref(),
        endpoints: captured
            .endpoints
            .iter()
            .map(|endpoint| json_endpoint(endpoint, &captured.processes))
            .collect(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_port_table(
    captured: &CapturedPort,
    expectation: Option<&str>,
    passed: Option<bool>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, passed)) = expectation.zip(passed) {
        output.push_str(&format!(
            "PORT CHECK {}  expected {}; matched {} endpoint(s)\n",
            if passed { "PASS" } else { "FAIL" },
            expectation,
            captured.endpoints.len()
        ));
    }
    output.push_str(&format!(
        "LOCAL PORT {}  protocol {}  scope {}  {} endpoint(s), {} known owner(s)\n",
        captured.port,
        captured.protocol.label(),
        captured.scope.label(),
        captured.endpoints.len(),
        known_owner_count(&captured.endpoints),
    ));
    if captured.endpoints.is_empty() {
        output.push_str("  [no matching endpoint visible]\n");
    } else {
        output.push_str(
            "PROTO LOCAL                    REMOTE                   STATE        PID      FD       USER         PROCESS      COMMAND\n",
        );
        for endpoint in &captured.endpoints {
            let process = endpoint.pid.and_then(|pid| captured.processes.get(&pid));
            output.push_str(&format!(
                "{:<5} {:<24} {:<24} {:<12} {:>8} {:<8} {:<12} {:<12} {}\n",
                sanitize_terminal_text(&endpoint.protocol),
                sanitize_terminal_text(&endpoint.local_endpoint),
                if endpoint.remote_endpoint.is_empty() {
                    "-".into()
                } else {
                    sanitize_terminal_text(&endpoint.remote_endpoint)
                },
                sanitize_terminal_text(&endpoint.state),
                endpoint
                    .pid
                    .map(|pid| pid.as_u32().to_string())
                    .unwrap_or_else(|| "-".into()),
                sanitize_terminal_text(&endpoint.fd),
                process
                    .map(|process| sanitize_terminal_text(&process.user))
                    .unwrap_or_else(|| "-".into()),
                sanitize_terminal_text(&endpoint.process),
                process
                    .map(process_command_line)
                    .map(|command| sanitize_terminal_text(&command))
                    .unwrap_or_else(|| "[owner unavailable]".into()),
            ));
            if !endpoint.namespace.is_empty() {
                output.push_str(&format!(
                    "      namespace {}\n",
                    sanitize_terminal_text(&endpoint.namespace)
                ));
            }
        }
    }
    if let Some(warning) = &captured.warning {
        output.push_str(&format!("WARNING  {}\n", sanitize_terminal_text(warning)));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn endpoint(protocol: &str, local: &str, remote: &str, state: &str) -> NetworkEndpoint {
        NetworkEndpoint {
            pid: Some(Pid::from_u32(42)),
            process: "api".into(),
            fd: "7".into(),
            protocol: protocol.into(),
            local_endpoint: local.into(),
            remote_endpoint: remote.into(),
            state: state.into(),
            namespace: "net:[123]".into(),
        }
    }

    fn process() -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(42),
            parent: Some(Pid::from_u32(1)),
            name: "api".into(),
            command: "/srv/api\n--port 8080".into(),
            executable: "/srv/api".into(),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu: 0.0,
            memory: 0,
            read_rate: 0,
            write_rate: 0,
            start_time: 100,
            runtime: 10,
            status: "Sleep".into(),
        }
    }

    fn captured() -> CapturedPort {
        CapturedPort {
            port: 8_080,
            protocol: PortProtocol::Tcp,
            scope: NetworkScope::Listeners,
            generated_at_unix_ms: 1_700_000_000_000,
            system_process_count: 10,
            processes: [(Pid::from_u32(42), process())].into_iter().collect(),
            endpoints: vec![endpoint("TCP", "[::]:8080", "", "LISTEN")],
            warning: None,
        }
    }

    #[test]
    fn filters_exact_local_ports_protocols_and_scope() {
        let endpoints = vec![
            endpoint("TCP", "127.0.0.1:8080", "", "LISTEN"),
            endpoint("TCP", "127.0.0.1:8080", "10.0.0.2:55000", "ESTABLISHED"),
            endpoint("UDP", "[::]:8080", "", "BOUND"),
            endpoint("TCP", "*:18080", "", "LISTEN"),
        ];
        assert_eq!(endpoint_port("[::1]:8080"), Some(8_080));
        assert_eq!(
            matching_endpoints(
                &endpoints,
                8_080,
                PortProtocol::Any,
                NetworkScope::Listeners
            )
            .len(),
            2
        );
        assert_eq!(
            matching_endpoints(&endpoints, 8_080, PortProtocol::Tcp, NetworkScope::All).len(),
            2
        );
        assert!(
            matching_endpoints(&endpoints, 80, PortProtocol::Any, NetworkScope::All).is_empty()
        );
    }

    #[test]
    fn port_outputs_link_owners_and_expose_policy() {
        let captured = captured();
        let table = render_port_table(&captured, Some("at least one match"), Some(true));
        assert!(table.starts_with("PORT CHECK PASS"));
        assert!(table.contains("/srv/api --port 8080"));
        assert!(!table.contains("/srv/api\n--port"));

        let json: Value = serde_json::from_str(
            &render_port_json(&captured, Some("at least one match"), Some(true)).unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], PORT_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["local_port"], 8_080);
        assert_eq!(json["scope"], "listeners");
        assert_eq!(json["policy"]["passed"], true);
        assert_eq!(json["known_owner_count"], 1);
        assert_eq!(json["endpoints"][0]["pid"], 42);
        assert_eq!(json["endpoints"][0]["path"], "/srv/api");
    }
}
