use std::{
    collections::{HashMap, HashSet},
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

const NET_SCHEMA: &str = "psmore.network-connections";
const NET_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointKind {
    Peer,
    Listener,
    Open,
}

impl EndpointKind {
    fn classify(endpoint: &NetworkEndpoint) -> Self {
        if has_peer(endpoint) {
            Self::Peer
        } else if endpoint.is_listener() {
            Self::Listener
        } else {
            Self::Open
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Listener => "listener",
            Self::Open => "open",
        }
    }

    fn table_label(self) -> &'static str {
        match self {
            Self::Peer => "PEER",
            Self::Listener => "LISTEN",
            Self::Open => "OPEN",
        }
    }

    fn sort_rank(self) -> u8 {
        match self {
            Self::Peer => 0,
            Self::Listener => 1,
            Self::Open => 2,
        }
    }
}

fn has_peer(endpoint: &NetworkEndpoint) -> bool {
    if endpoint.is_listener() {
        return false;
    }
    !endpoint.remote_endpoint.is_empty()
        || matches!(endpoint.state.as_str(), "CONNECTED" | "CONNECTING")
}

fn is_connected_peer(endpoint: &NetworkEndpoint) -> bool {
    has_peer(endpoint) && !matches!(endpoint.state.as_str(), "CLOSED" | "CLOSE" | "UNKNOWN")
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
                "{} {} {} {} {}",
                process.name,
                process.user,
                process_path(process),
                process_command_line(process),
                process.cwd,
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
        EndpointKind::classify(endpoint).label(),
        process_context,
    )
    .to_lowercase()
    .contains(&query.to_lowercase())
}

fn matching_endpoints(
    endpoints: &[NetworkEndpoint],
    processes: &HashMap<Pid, ProcessInfo>,
    protocol: ListenProtocol,
    connected_only: bool,
    state: Option<&str>,
    query: &str,
) -> Vec<NetworkEndpoint> {
    let mut matches: Vec<NetworkEndpoint> = endpoints
        .iter()
        .filter(|endpoint| protocol_matches(protocol, endpoint))
        .filter(|endpoint| !connected_only || is_connected_peer(endpoint))
        .filter(|endpoint| {
            state
                .map(|state| endpoint.state.eq_ignore_ascii_case(state))
                .unwrap_or(true)
        })
        .filter(|endpoint| {
            endpoint_matches_query(
                endpoint,
                endpoint.pid.and_then(|pid| processes.get(&pid)),
                query,
            )
        })
        .cloned()
        .collect();
    matches.sort_by(|left, right| {
        (
            EndpointKind::classify(left).sort_rank(),
            protocol_rank(&left.protocol),
            &left.state,
            &left.remote_endpoint,
            &left.local_endpoint,
            &left.namespace,
            left.pid.map(Pid::as_u32),
            &left.fd,
        )
            .cmp(&(
                EndpointKind::classify(right).sort_rank(),
                protocol_rank(&right.protocol),
                &right.state,
                &right.remote_endpoint,
                &right.local_endpoint,
                &right.namespace,
                right.pid.map(Pid::as_u32),
                &right.fd,
            ))
    });
    matches
}

fn protocol_rank(protocol: &str) -> u8 {
    match protocol {
        "TCP" => 0,
        "UDP" => 1,
        "UNIX" => 2,
        _ => 3,
    }
}

fn unique_route_key(endpoint: &NetworkEndpoint) -> (&str, &str, &str, &str, &str) {
    (
        &endpoint.protocol,
        &endpoint.local_endpoint,
        &endpoint.remote_endpoint,
        &endpoint.state,
        &endpoint.namespace,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetPolicyStatus {
    Passed,
    Violated,
    Inconclusive,
}

impl NetPolicyStatus {
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

pub(crate) struct CapturedNetworkConnections {
    generated_at_unix_ms: u64,
    query: String,
    protocol: ListenProtocol,
    connected_only: bool,
    state: Option<String>,
    result_limit: Option<usize>,
    system_process_count: usize,
    processes: HashMap<Pid, ProcessInfo>,
    endpoints: Vec<NetworkEndpoint>,
    collection_complete: bool,
    warning: Option<String>,
}

impl CapturedNetworkConnections {
    pub(crate) fn evaluate_policy(&self, expectation: CheckExpectation) -> NetPolicyStatus {
        if !self.endpoints.is_empty() {
            if expectation.passes(self.endpoints.len()) {
                NetPolicyStatus::Passed
            } else {
                NetPolicyStatus::Violated
            }
        } else if !self.collection_complete {
            NetPolicyStatus::Inconclusive
        } else if expectation.passes(0) {
            NetPolicyStatus::Passed
        } else {
            NetPolicyStatus::Violated
        }
    }

    fn returned_count(&self) -> usize {
        self.result_limit
            .unwrap_or(self.endpoints.len())
            .min(self.endpoints.len())
    }

    fn visible_endpoints(&self) -> impl Iterator<Item = &NetworkEndpoint> {
        self.endpoints.iter().take(self.returned_count())
    }

    fn unique_route_count(&self) -> usize {
        self.endpoints
            .iter()
            .map(unique_route_key)
            .collect::<HashSet<_>>()
            .len()
    }

    fn peer_reference_count(&self) -> usize {
        self.endpoints
            .iter()
            .filter(|endpoint| has_peer(endpoint))
            .count()
    }

    fn listener_reference_count(&self) -> usize {
        self.endpoints
            .iter()
            .filter(|endpoint| endpoint.is_listener())
            .count()
    }

    fn known_owner_count(&self) -> usize {
        self.endpoints
            .iter()
            .filter_map(|endpoint| endpoint.pid)
            .collect::<HashSet<_>>()
            .len()
    }
}

pub(crate) fn capture_network_connections(
    query: &str,
    protocol: ListenProtocol,
    connected_only: bool,
    state: Option<&str>,
    result_limit: Option<usize>,
) -> CapturedNetworkConnections {
    let mut provider = NativeProcessProvider::new();
    let processes: HashMap<Pid, ProcessInfo> = provider
        .refresh()
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let scan = scan_network(&processes);
    let endpoints = matching_endpoints(
        &scan.endpoints,
        &processes,
        protocol,
        connected_only,
        state,
        query,
    );
    CapturedNetworkConnections {
        generated_at_unix_ms: unix_millis(),
        query: query.into(),
        protocol,
        connected_only,
        state: state.map(str::to_string),
        result_limit,
        system_process_count: processes
            .len()
            .saturating_sub(usize::from(processes.contains_key(&Pid::from_u32(0))))
            .saturating_sub(usize::from(
                processes.contains_key(&Pid::from_u32(std::process::id())),
            )),
        processes,
        endpoints,
        collection_complete: scan.warning.is_none(),
        warning: scan.warning,
    }
}

#[derive(Debug, Serialize)]
struct JsonNetworkConnections<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    interpretation: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    query: Option<&'a str>,
    protocol: &'static str,
    connected_only: bool,
    state: Option<&'a str>,
    result_limit: Option<usize>,
    system_process_count: usize,
    unique_route_count: usize,
    socket_reference_count: usize,
    peer_reference_count: usize,
    listener_reference_count: usize,
    returned_socket_reference_count: usize,
    rows_truncated: bool,
    known_owner_count: usize,
    unresolved_socket_count: usize,
    collection_complete: bool,
    policy: Option<JsonPolicy<'a>>,
    warning: Option<&'a str>,
    connections: Vec<JsonConnection>,
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
struct JsonConnection {
    kind: &'static str,
    peer_evidence: bool,
    listener: bool,
    protocol: String,
    local_endpoint: String,
    remote_endpoint: Option<String>,
    state: String,
    pid: Option<u32>,
    fd: String,
    process: String,
    user: Option<String>,
    path: Option<String>,
    command: Option<String>,
    namespace: Option<String>,
}

fn json_connection(
    endpoint: &NetworkEndpoint,
    processes: &HashMap<Pid, ProcessInfo>,
) -> JsonConnection {
    let process = endpoint.pid.and_then(|pid| processes.get(&pid));
    JsonConnection {
        kind: EndpointKind::classify(endpoint).label(),
        peer_evidence: has_peer(endpoint),
        listener: endpoint.is_listener(),
        protocol: sanitize_terminal_text(&endpoint.protocol),
        local_endpoint: sanitize_terminal_text(&endpoint.local_endpoint),
        remote_endpoint: (!endpoint.remote_endpoint.is_empty())
            .then(|| sanitize_terminal_text(&endpoint.remote_endpoint)),
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

pub(crate) fn render_network_json(
    captured: &CapturedNetworkConnections,
    expectation: Option<&str>,
    policy_status: Option<NetPolicyStatus>,
) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonNetworkConnections {
        schema: NET_SCHEMA,
        schema_version: NET_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, user, socket, peer, and namespace information; review before sharing.",
        interpretation: "local and remote endpoints are kernel socket evidence; no inbound or outbound initiation direction is inferred",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        query: (!captured.query.is_empty()).then_some(captured.query.as_str()),
        protocol: captured.protocol.label(),
        connected_only: captured.connected_only,
        state: captured.state.as_deref(),
        result_limit: captured.result_limit,
        system_process_count: captured.system_process_count,
        unique_route_count: captured.unique_route_count(),
        socket_reference_count: captured.endpoints.len(),
        peer_reference_count: captured.peer_reference_count(),
        listener_reference_count: captured.listener_reference_count(),
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
                detail: (status == NetPolicyStatus::Inconclusive).then_some(
                    "zero visible sockets cannot prove absence because network collection was incomplete",
                ),
            }),
        warning: captured.warning.as_deref(),
        connections: captured
            .visible_endpoints()
            .map(|endpoint| json_connection(endpoint, &captured.processes))
            .collect(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_network_table(
    captured: &CapturedNetworkConnections,
    expectation: Option<&str>,
    policy_status: Option<NetPolicyStatus>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, status)) = expectation.zip(policy_status) {
        output.push_str(&format!(
            "NET CHECK {}  expected {}; matched {} socket reference(s)\n",
            match status {
                NetPolicyStatus::Passed => "PASS",
                NetPolicyStatus::Violated => "FAIL",
                NetPolicyStatus::Inconclusive => "INCONCLUSIVE",
            },
            expectation,
            captured.endpoints.len(),
        ));
    }
    output.push_str(&format!(
        "NETWORK  {} route(s), {} socket reference(s), {} peer, {} listener, {} owner(s), showing {}\n",
        captured.unique_route_count(),
        captured.endpoints.len(),
        captured.peer_reference_count(),
        captured.listener_reference_count(),
        captured.known_owner_count(),
        captured.returned_count(),
    ));
    output.push_str(&format!(
        "protocol {}  scope {}  state {}  filter {}  collection {}\n",
        captured.protocol.label(),
        if captured.connected_only {
            "connected/peer"
        } else {
            "all sockets"
        },
        captured.state.as_deref().unwrap_or("any"),
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
        output.push_str("  [no matching socket visible]\n");
    } else {
        output.push_str(
            "KIND   PROTO STATE        LOCAL -> PEER                                        PID FD       USER         PROCESS      COMMAND\n",
        );
        for endpoint in captured.visible_endpoints() {
            let process = endpoint.pid.and_then(|pid| captured.processes.get(&pid));
            let route = if endpoint.remote_endpoint.is_empty() {
                endpoint.local_endpoint.clone()
            } else {
                format!(
                    "{} -> {}",
                    endpoint.local_endpoint, endpoint.remote_endpoint
                )
            };
            output.push_str(&format!(
                "{:<6} {:<5} {:<12} {:<52} {:>7} {:<8} {:<12} {:<12} {}\n",
                EndpointKind::classify(endpoint).table_label(),
                sanitize_terminal_text(&endpoint.protocol),
                sanitize_terminal_text(&endpoint.state),
                sanitize_terminal_text(&route),
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
                    "       namespace {}\n",
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
    }
    output.push_str(
        "INTERPRET  LOCAL -> PEER is endpoint evidence only; psmore does not infer who initiated an established route.\n",
    );
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

    fn endpoint(
        protocol: &str,
        state: &str,
        local: &str,
        remote: &str,
        pid: Option<u32>,
    ) -> NetworkEndpoint {
        NetworkEndpoint {
            pid: pid.map(Pid::from_u32),
            process: pid.map(|_| "api").unwrap_or("[owner unavailable]").into(),
            fd: pid.map(|_| "7").unwrap_or("-").into(),
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
            command: "/srv/api\n--peer 203.0.113.10".into(),
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

    fn captured(complete: bool) -> CapturedNetworkConnections {
        CapturedNetworkConnections {
            generated_at_unix_ms: 1_700_000_000_000,
            query: "api".into(),
            protocol: ListenProtocol::Any,
            connected_only: false,
            state: None,
            result_limit: Some(1),
            system_process_count: 10,
            processes: [(Pid::from_u32(42), process())].into_iter().collect(),
            endpoints: vec![
                endpoint(
                    "TCP",
                    "ESTABLISHED",
                    "10.0.0.2:50000",
                    "203.0.113.10:443",
                    Some(42),
                ),
                endpoint("TCP", "LISTEN", "0.0.0.0:8080", "", Some(42)),
            ],
            collection_complete: complete,
            warning: (!complete).then(|| "protected processes".into()),
        }
    }

    #[test]
    fn peer_classification_does_not_invent_direction() {
        let established = endpoint(
            "TCP",
            "ESTABLISHED",
            "10.0.0.2:50000",
            "203.0.113.10:443",
            Some(42),
        );
        assert!(has_peer(&established));
        assert!(is_connected_peer(&established));
        assert_eq!(EndpointKind::classify(&established), EndpointKind::Peer);
        assert!(!has_peer(&endpoint(
            "TCP",
            "LISTEN",
            "0.0.0.0:8080",
            "",
            Some(42)
        )));
        assert!(!has_peer(&endpoint(
            "UDP",
            "BOUND",
            "0.0.0.0:5353",
            "",
            Some(42)
        )));
        assert!(has_peer(&endpoint(
            "UNIX",
            "CONNECTED",
            "/tmp/api.sock",
            "",
            Some(42)
        )));
        let closed = endpoint(
            "TCP",
            "CLOSED",
            "10.0.0.2:50000",
            "203.0.113.10:443",
            Some(42),
        );
        assert!(has_peer(&closed));
        assert!(!is_connected_peer(&closed));
    }

    #[test]
    fn filters_protocol_peer_state_and_process_context() {
        let processes = [(Pid::from_u32(42), process())].into_iter().collect();
        let endpoints = vec![
            endpoint(
                "TCP",
                "ESTABLISHED",
                "10.0.0.2:50000",
                "203.0.113.10:443",
                Some(42),
            ),
            endpoint("TCP", "LISTEN", "0.0.0.0:8080", "", Some(42)),
            endpoint("UDP", "BOUND", "0.0.0.0:5353", "", Some(42)),
        ];
        let matches = matching_endpoints(
            &endpoints,
            &processes,
            ListenProtocol::Tcp,
            true,
            Some("ESTABLISHED"),
            "deploy",
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].remote_endpoint, "203.0.113.10:443");
        assert_eq!(
            matching_endpoints(
                &endpoints,
                &processes,
                ListenProtocol::Any,
                false,
                None,
                "--peer 203.0.113.10",
            )
            .len(),
            3
        );
    }

    #[test]
    fn zero_matches_with_incomplete_scan_is_inconclusive() {
        let mut captured = captured(false);
        captured.endpoints.clear();
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::None),
            NetPolicyStatus::Inconclusive
        );
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::Any),
            NetPolicyStatus::Inconclusive
        );
    }

    #[test]
    fn renders_versioned_route_owner_and_truncation_evidence() {
        let captured = captured(true);
        let json: Value = serde_json::from_str(
            &render_network_json(
                &captured,
                Some("no matches"),
                Some(NetPolicyStatus::Violated),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], NET_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["unique_route_count"], 2);
        assert_eq!(json["peer_reference_count"], 1);
        assert_eq!(json["listener_reference_count"], 1);
        assert_eq!(json["returned_socket_reference_count"], 1);
        assert_eq!(json["rows_truncated"], true);
        assert_eq!(json["connections"][0]["kind"], "peer");
        assert_eq!(
            json["connections"][0]["remote_endpoint"],
            "203.0.113.10:443"
        );
        assert_eq!(
            json["connections"][0]["command"],
            "/srv/api --peer 203.0.113.10"
        );
        assert!(
            json["interpretation"]
                .as_str()
                .unwrap()
                .contains("no inbound or outbound")
        );

        let table = render_network_table(
            &captured,
            Some("no matches"),
            Some(NetPolicyStatus::Violated),
        );
        assert!(table.contains("NET CHECK FAIL"));
        assert!(table.contains("10.0.0.2:50000 -> 203.0.113.10:443"));
        assert!(table.contains("does not infer who initiated"));
        assert!(!table.contains("/srv/api\n--peer"));
    }
}
