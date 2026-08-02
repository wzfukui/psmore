use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    cli::{CheckExpectation, ListenProtocol},
    model::{
        ProcessInfo, process_command_for_output, process_command_line, process_path,
        sanitize_terminal_text,
    },
    network::{NetworkEndpoint, scan_network},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const LISTEN_SCHEMA: &str = "psmore.listeners";
const LISTEN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindExposure {
    Wildcard,
    Network,
    Loopback,
    Local,
    Unknown,
}

impl BindExposure {
    fn label(self) -> &'static str {
        match self {
            Self::Wildcard => "wildcard",
            Self::Network => "network",
            Self::Loopback => "loopback",
            Self::Local => "local",
            Self::Unknown => "unknown",
        }
    }

    fn table_label(self) -> &'static str {
        match self {
            Self::Wildcard => "WILDCARD",
            Self::Network => "NETWORK",
            Self::Loopback => "loopback",
            Self::Local => "local",
            Self::Unknown => "unknown",
        }
    }

    fn is_exposed(self) -> bool {
        matches!(self, Self::Wildcard | Self::Network)
    }

    fn sort_rank(self) -> u8 {
        match self {
            Self::Wildcard => 0,
            Self::Network => 1,
            Self::Loopback => 2,
            Self::Local => 3,
            Self::Unknown => 4,
        }
    }
}

fn inet_host(endpoint: &str) -> Option<&str> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split_once("]:").map(|(host, _)| host);
    }
    endpoint.rsplit_once(':').map(|(host, _)| host)
}

fn endpoint_port(endpoint: &NetworkEndpoint) -> Option<u16> {
    if endpoint.protocol == "UNIX" {
        return None;
    }
    endpoint
        .local_endpoint
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
}

fn bind_exposure(endpoint: &NetworkEndpoint) -> BindExposure {
    if endpoint.protocol == "UNIX" {
        return BindExposure::Local;
    }
    let Some(host) = inet_host(&endpoint.local_endpoint) else {
        return BindExposure::Unknown;
    };
    let host = host.trim_matches(['[', ']']);
    if matches!(host, "*" | "0.0.0.0" | "::") {
        return BindExposure::Wildcard;
    }
    match host.parse::<IpAddr>() {
        Ok(address) if is_loopback(address) => BindExposure::Loopback,
        Ok(_) => BindExposure::Network,
        Err(_) => BindExposure::Unknown,
    }
}

fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .map(|address| address.is_loopback())
                    .unwrap_or(false)
        }
    }
}

fn protocol_matches(protocol: ListenProtocol, endpoint: &NetworkEndpoint) -> bool {
    match protocol {
        ListenProtocol::Any => matches!(endpoint.protocol.as_str(), "TCP" | "UDP" | "UNIX"),
        ListenProtocol::Tcp => endpoint.protocol == "TCP",
        ListenProtocol::Udp => endpoint.protocol == "UDP",
        ListenProtocol::Unix => endpoint.protocol == "UNIX",
    }
}

fn endpoint_matches_query(
    endpoint: &NetworkEndpoint,
    process: Option<&ProcessInfo>,
    query: &str,
) -> bool {
    if query.is_empty() {
        return true;
    }
    let process_context = process
        .map(|process| {
            format!(
                "{} {} {} {}",
                process.user,
                process_path(process),
                process_command_line(process),
                process.cwd
            )
        })
        .unwrap_or_default();
    format!(
        "{} {} {} {} {} {} {} {} {} {}",
        endpoint.protocol,
        endpoint.local_endpoint,
        endpoint.remote_endpoint,
        endpoint.state,
        endpoint.process,
        endpoint.pid.map(Pid::as_u32).unwrap_or_default(),
        endpoint.fd,
        endpoint.namespace,
        bind_exposure(endpoint).label(),
        process_context,
    )
    .to_lowercase()
    .contains(&query.to_lowercase())
}

fn matching_listeners(
    endpoints: &[NetworkEndpoint],
    processes: &HashMap<Pid, ProcessInfo>,
    protocol: ListenProtocol,
    exposed_only: bool,
    query: &str,
) -> Vec<NetworkEndpoint> {
    let mut listeners: Vec<NetworkEndpoint> = endpoints
        .iter()
        .filter(|endpoint| endpoint.is_listener())
        .filter(|endpoint| protocol_matches(protocol, endpoint))
        .filter(|endpoint| !exposed_only || bind_exposure(endpoint).is_exposed())
        .filter(|endpoint| {
            endpoint_matches_query(
                endpoint,
                endpoint.pid.and_then(|pid| processes.get(&pid)),
                query,
            )
        })
        .cloned()
        .collect();
    listeners.sort_by(|left, right| {
        (
            bind_exposure(left).sort_rank(),
            protocol_rank(&left.protocol),
            endpoint_port(left),
            &left.local_endpoint,
            &left.namespace,
            left.pid.map(Pid::as_u32),
            &left.fd,
        )
            .cmp(&(
                bind_exposure(right).sort_rank(),
                protocol_rank(&right.protocol),
                endpoint_port(right),
                &right.local_endpoint,
                &right.namespace,
                right.pid.map(Pid::as_u32),
                &right.fd,
            ))
    });
    listeners
}

fn protocol_rank(protocol: &str) -> u8 {
    match protocol {
        "TCP" => 0,
        "UDP" => 1,
        "UNIX" => 2,
        _ => 3,
    }
}

fn unique_bind_key(endpoint: &NetworkEndpoint) -> (&str, &str, &str) {
    (
        &endpoint.protocol,
        &endpoint.local_endpoint,
        &endpoint.namespace,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ListenPolicyStatus {
    Passed,
    Violated,
    Inconclusive,
}

impl ListenPolicyStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Passed => "pass",
            Self::Violated => "fail",
            Self::Inconclusive => "inconclusive",
        }
    }

    fn passed(self) -> Option<bool> {
        match self {
            Self::Passed => Some(true),
            Self::Violated => Some(false),
            Self::Inconclusive => None,
        }
    }
}

pub(crate) struct CapturedListeners {
    generated_at_unix_ms: u64,
    query: String,
    protocol: ListenProtocol,
    exposed_only: bool,
    result_limit: Option<usize>,
    system_process_count: usize,
    processes: HashMap<Pid, ProcessInfo>,
    endpoints: Vec<NetworkEndpoint>,
    collection_complete: bool,
    warning: Option<String>,
}

impl CapturedListeners {
    pub(crate) fn evaluate_policy(&self, expectation: CheckExpectation) -> ListenPolicyStatus {
        if !self.endpoints.is_empty() {
            if expectation.passes(self.endpoints.len()) {
                ListenPolicyStatus::Passed
            } else {
                ListenPolicyStatus::Violated
            }
        } else if !self.collection_complete {
            ListenPolicyStatus::Inconclusive
        } else if expectation.passes(0) {
            ListenPolicyStatus::Passed
        } else {
            ListenPolicyStatus::Violated
        }
    }

    fn returned_count(&self) -> usize {
        self.result_limit
            .map(|limit| self.endpoints.len().min(limit))
            .unwrap_or(self.endpoints.len())
    }

    fn visible_endpoints(&self) -> impl Iterator<Item = &NetworkEndpoint> {
        self.endpoints
            .iter()
            .take(self.result_limit.unwrap_or(self.endpoints.len()))
    }

    fn unique_bind_count(&self) -> usize {
        self.endpoints
            .iter()
            .map(unique_bind_key)
            .collect::<HashSet<_>>()
            .len()
    }

    fn exposed_bind_count(&self) -> usize {
        self.endpoints
            .iter()
            .filter(|endpoint| bind_exposure(endpoint).is_exposed())
            .map(unique_bind_key)
            .collect::<HashSet<_>>()
            .len()
    }

    fn known_owner_count(&self) -> usize {
        self.endpoints
            .iter()
            .filter_map(|endpoint| endpoint.pid)
            .collect::<HashSet<_>>()
            .len()
    }

    pub(crate) fn diagnostic_summary(&self) -> ListenerDiagnosticSummary {
        ListenerDiagnosticSummary {
            exposed_bind_count: self.exposed_bind_count(),
            socket_reference_count: self.endpoints.len(),
            known_owner_count: self.known_owner_count(),
            unresolved_socket_count: self
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.pid.is_none())
                .count(),
            collection_complete: self.collection_complete,
            warning: self.warning.clone(),
            listeners: self
                .visible_endpoints()
                .map(|endpoint| {
                    let process = endpoint.pid.and_then(|pid| self.processes.get(&pid));
                    ListenerDiagnosticItem {
                        exposure: bind_exposure(endpoint).label(),
                        protocol: endpoint.protocol.clone(),
                        local_endpoint: endpoint.local_endpoint.clone(),
                        pid: endpoint.pid.map(Pid::as_u32),
                        process: endpoint.process.clone(),
                        user: process.map(|process| process.user.clone()),
                        command: process.map(process_command_line),
                        namespace: (!endpoint.namespace.is_empty())
                            .then(|| endpoint.namespace.clone()),
                    }
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ListenerDiagnosticSummary {
    pub(crate) exposed_bind_count: usize,
    pub(crate) socket_reference_count: usize,
    pub(crate) known_owner_count: usize,
    pub(crate) unresolved_socket_count: usize,
    pub(crate) collection_complete: bool,
    pub(crate) warning: Option<String>,
    pub(crate) listeners: Vec<ListenerDiagnosticItem>,
}

#[derive(Clone, Debug)]
pub(crate) struct ListenerDiagnosticItem {
    pub(crate) exposure: &'static str,
    pub(crate) protocol: String,
    pub(crate) local_endpoint: String,
    pub(crate) pid: Option<u32>,
    pub(crate) process: String,
    pub(crate) user: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) namespace: Option<String>,
}

pub(crate) fn capture_listeners(
    query: &str,
    protocol: ListenProtocol,
    exposed_only: bool,
    result_limit: Option<usize>,
) -> CapturedListeners {
    let mut provider = NativeProcessProvider::new();
    let processes: HashMap<Pid, ProcessInfo> = provider
        .refresh()
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let scan = scan_network(&processes);
    let endpoints = matching_listeners(&scan.endpoints, &processes, protocol, exposed_only, query);
    CapturedListeners {
        generated_at_unix_ms: unix_millis(),
        query: query.into(),
        protocol,
        exposed_only,
        result_limit,
        system_process_count: processes
            .len()
            .saturating_sub(usize::from(processes.contains_key(&Pid::from_u32(0)))),
        processes,
        endpoints,
        collection_complete: scan.warning.is_none(),
        warning: scan.warning,
    }
}

#[derive(Debug, Serialize)]
struct JsonListeners<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    query: Option<&'a str>,
    protocol: &'static str,
    exposed_only: bool,
    result_limit: Option<usize>,
    system_process_count: usize,
    unique_bind_count: usize,
    exposed_bind_count: usize,
    socket_reference_count: usize,
    returned_socket_reference_count: usize,
    rows_truncated: bool,
    known_owner_count: usize,
    unresolved_socket_count: usize,
    collection_complete: bool,
    policy: Option<JsonPolicy<'a>>,
    warning: Option<&'a str>,
    listeners: Vec<JsonListener>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonPolicy<'a> {
    expectation: &'a str,
    status: &'static str,
    passed: Option<bool>,
    detail: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct JsonListener {
    exposure: &'static str,
    exposed: bool,
    protocol: String,
    local_endpoint: String,
    state: String,
    pid: Option<u32>,
    fd: String,
    process: String,
    user: Option<String>,
    path: Option<String>,
    command: Option<String>,
    namespace: Option<String>,
}

fn json_listener(
    endpoint: &NetworkEndpoint,
    processes: &HashMap<Pid, ProcessInfo>,
) -> JsonListener {
    let process = endpoint.pid.and_then(|pid| processes.get(&pid));
    let exposure = bind_exposure(endpoint);
    JsonListener {
        exposure: exposure.label(),
        exposed: exposure.is_exposed(),
        protocol: sanitize_terminal_text(&endpoint.protocol),
        local_endpoint: sanitize_terminal_text(&endpoint.local_endpoint),
        state: sanitize_terminal_text(&endpoint.state),
        pid: endpoint.pid.map(Pid::as_u32),
        fd: sanitize_terminal_text(&endpoint.fd),
        process: sanitize_terminal_text(&endpoint.process),
        user: process.map(|process| sanitize_terminal_text(&process.user)),
        path: process
            .map(process_path)
            .map(|path| sanitize_terminal_text(&path)),
        command: process
            .map(process_command_for_output)
            .map(|command| sanitize_terminal_text(&command)),
        namespace: (!endpoint.namespace.is_empty())
            .then(|| sanitize_terminal_text(&endpoint.namespace)),
    }
}

pub(crate) fn render_listeners_json(
    captured: &CapturedListeners,
    expectation: Option<&str>,
    policy_status: Option<ListenPolicyStatus>,
) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonListeners {
        schema: LISTEN_SCHEMA,
        schema_version: LISTEN_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, user, socket, and namespace information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        query: (!captured.query.is_empty()).then_some(captured.query.as_str()),
        protocol: captured.protocol.label(),
        exposed_only: captured.exposed_only,
        result_limit: captured.result_limit,
        system_process_count: captured.system_process_count,
        unique_bind_count: captured.unique_bind_count(),
        exposed_bind_count: captured.exposed_bind_count(),
        socket_reference_count: captured.endpoints.len(),
        returned_socket_reference_count: captured.returned_count(),
        rows_truncated: captured.returned_count() < captured.endpoints.len(),
        known_owner_count: captured.known_owner_count(),
        unresolved_socket_count: captured
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.pid.is_none())
            .count(),
        collection_complete: captured.collection_complete,
        policy: expectation
            .zip(policy_status)
            .map(|(expectation, status)| JsonPolicy {
                expectation,
                status: status.label(),
                passed: status.passed(),
                detail: (status == ListenPolicyStatus::Inconclusive).then_some(
                    "zero visible listeners cannot prove absence because network collection was incomplete",
                ),
            }),
        warning: captured.warning.as_deref(),
        listeners: captured
            .visible_endpoints()
            .map(|endpoint| json_listener(endpoint, &captured.processes))
            .collect(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_listeners_table(
    captured: &CapturedListeners,
    expectation: Option<&str>,
    policy_status: Option<ListenPolicyStatus>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, status)) = expectation.zip(policy_status) {
        output.push_str(&format!(
            "LISTEN CHECK {}  expected {}; matched {} socket reference(s)\n",
            match status {
                ListenPolicyStatus::Passed => "PASS",
                ListenPolicyStatus::Violated => "FAIL",
                ListenPolicyStatus::Inconclusive => "INCONCLUSIVE",
            },
            expectation,
            captured.endpoints.len(),
        ));
    }
    output.push_str(&format!(
        "LISTENERS  {} bind(s), {} exposed, {} socket reference(s), {} owner(s), showing {}\n",
        captured.unique_bind_count(),
        captured.exposed_bind_count(),
        captured.endpoints.len(),
        captured.known_owner_count(),
        captured.returned_count(),
    ));
    output.push_str(&format!(
        "protocol {}  scope {}  filter {}  collection {}\n",
        captured.protocol.label(),
        if captured.exposed_only {
            "exposed"
        } else {
            "all"
        },
        if captured.query.is_empty() {
            "[none]".into()
        } else {
            format!("\"{}\"", sanitize_terminal_text(&captured.query))
        },
        if captured.collection_complete {
            "complete"
        } else {
            "incomplete"
        },
    ));
    if captured.endpoints.is_empty() {
        output.push_str("  [no matching listener visible]\n");
    } else {
        output.push_str(
            "EXPOSURE PROTO LOCAL                          STATE        PID FD       USER         PROCESS      COMMAND\n",
        );
        for endpoint in captured.visible_endpoints() {
            let process = endpoint.pid.and_then(|pid| captured.processes.get(&pid));
            output.push_str(&format!(
                "{:<8} {:<5} {:<30} {:<10} {:>7} {:<8} {:<12} {:<12} {}\n",
                bind_exposure(endpoint).table_label(),
                sanitize_terminal_text(&endpoint.protocol),
                sanitize_terminal_text(&endpoint.local_endpoint),
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
                    .map(process_command_for_output)
                    .map(|command| sanitize_terminal_text(&command))
                    .unwrap_or_else(|| "[owner unavailable]".into()),
            ));
            if !endpoint.namespace.is_empty() {
                output.push_str(&format!(
                    "         namespace {}\n",
                    sanitize_terminal_text(&endpoint.namespace)
                ));
            }
        }
        if captured.returned_count() < captured.endpoints.len() {
            output.push_str(&format!(
                "  ... {} additional socket reference(s) hidden; use --limit all\n",
                captured.endpoints.len() - captured.returned_count()
            ));
        }
        if captured.exposed_bind_count() > 0 {
            output.push_str(
                "REVIEW  Confirm every WILDCARD/NETWORK bind is intended and protected by host, network, and application controls.\n",
            );
        }
    }
    if let Some(warning) = &captured.warning {
        output.push_str(&format!("WARNING  {}\n", sanitize_terminal_text(warning)));
    }
    output
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn endpoint(protocol: &str, local: &str, pid: Option<u32>) -> NetworkEndpoint {
        NetworkEndpoint {
            pid: pid.map(Pid::from_u32),
            process: pid.map(|_| "api").unwrap_or("[owner unavailable]").into(),
            fd: pid.map(|_| "7").unwrap_or("-").into(),
            protocol: protocol.into(),
            local_endpoint: local.into(),
            remote_endpoint: String::new(),
            state: if protocol == "UDP" { "BOUND" } else { "LISTEN" }.into(),
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

    fn captured(complete: bool) -> CapturedListeners {
        CapturedListeners {
            generated_at_unix_ms: 1_700_000_000_000,
            query: "api".into(),
            protocol: ListenProtocol::Any,
            exposed_only: false,
            result_limit: Some(1),
            system_process_count: 10,
            processes: [(Pid::from_u32(42), process())].into_iter().collect(),
            endpoints: vec![
                endpoint("TCP", "0.0.0.0:8080", Some(42)),
                endpoint("TCP", "127.0.0.1:9090", Some(42)),
            ],
            collection_complete: complete,
            warning: (!complete).then(|| "protected processes".into()),
        }
    }

    #[test]
    fn classifies_bind_exposure_and_filters_listeners() {
        assert_eq!(
            bind_exposure(&endpoint("TCP", "0.0.0.0:80", Some(42))),
            BindExposure::Wildcard
        );
        assert_eq!(
            bind_exposure(&endpoint("TCP", "[::1]:80", Some(42))),
            BindExposure::Loopback
        );
        assert_eq!(
            bind_exposure(&endpoint("TCP", "[::ffff:127.0.0.1]:80", Some(42))),
            BindExposure::Loopback
        );
        assert_eq!(
            bind_exposure(&endpoint("UDP", "192.168.1.5:53", Some(42))),
            BindExposure::Network
        );
        assert_eq!(
            bind_exposure(&endpoint("UNIX", "/tmp/api.sock", Some(42))),
            BindExposure::Local
        );

        let processes = [(Pid::from_u32(42), process())].into_iter().collect();
        let endpoints = vec![
            endpoint("TCP", "0.0.0.0:8080", Some(42)),
            endpoint("TCP", "127.0.0.1:9090", Some(42)),
            endpoint("UDP", "[::]:5353", None),
            endpoint("UNIX", "/tmp/api.sock", Some(42)),
        ];
        let exposed = matching_listeners(&endpoints, &processes, ListenProtocol::Any, true, "");
        assert_eq!(exposed.len(), 2);
        assert!(
            exposed
                .iter()
                .all(|endpoint| bind_exposure(endpoint).is_exposed())
        );
        assert_eq!(
            matching_listeners(&endpoints, &processes, ListenProtocol::Tcp, false, "deploy").len(),
            2
        );
    }

    #[test]
    fn zero_matches_with_incomplete_network_scan_is_inconclusive() {
        let mut captured = captured(false);
        captured.endpoints.clear();
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::None),
            ListenPolicyStatus::Inconclusive
        );
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::Any),
            ListenPolicyStatus::Inconclusive
        );
    }

    #[test]
    fn renders_versioned_exposure_owner_and_truncation_evidence() {
        let captured = captured(true);
        let json: Value = serde_json::from_str(
            &render_listeners_json(
                &captured,
                Some("no matches"),
                Some(ListenPolicyStatus::Violated),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], LISTEN_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["unique_bind_count"], 2);
        assert_eq!(json["exposed_bind_count"], 1);
        assert_eq!(json["socket_reference_count"], 2);
        assert_eq!(json["returned_socket_reference_count"], 1);
        assert_eq!(json["rows_truncated"], true);
        assert_eq!(json["listeners"][0]["exposure"], "wildcard");
        assert_eq!(json["listeners"][0]["command"], "/srv/api --port 8080");

        let table = render_listeners_table(
            &captured,
            Some("no matches"),
            Some(ListenPolicyStatus::Violated),
        );
        assert!(table.contains("LISTEN CHECK FAIL"));
        assert!(table.contains("WILDCARD"));
        assert!(table.contains("use --limit all"));
        assert!(!table.contains("/srv/api\n--port"));
    }
}
