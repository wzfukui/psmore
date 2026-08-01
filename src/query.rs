use sysinfo::Pid;

use crate::model::{ProcessInfo, ResourceAggregate, process_path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TextField {
    Any,
    Name,
    Command,
    Path,
    User,
    State,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NumericField {
    Pid,
    ParentPid,
    Children,
    Cpu,
    Memory,
    ReadRate,
    WriteRate,
    Age,
    TreeProcesses,
    TreeCpu,
    TreeMemory,
    TreeReadRate,
    TreeWriteRate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Comparator {
    Less,
    LessOrEqual,
    Equal,
    GreaterOrEqual,
    Greater,
}

impl Comparator {
    fn matches(self, actual: f64, expected: f64) -> bool {
        match self {
            Self::Less => actual < expected,
            Self::LessOrEqual => actual <= expected,
            Self::Equal => (actual - expected).abs() < f64::EPSILON,
            Self::GreaterOrEqual => actual >= expected,
            Self::Greater => actual > expected,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum QueryPredicate {
    Text {
        field: TextField,
        value: String,
    },
    Numeric {
        field: NumericField,
        comparator: Comparator,
        value: f64,
    },
}

#[derive(Clone, Debug, PartialEq)]
struct QueryTerm {
    negated: bool,
    predicate: QueryPredicate,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ProcessQuery {
    terms: Vec<QueryTerm>,
}

impl ProcessQuery {
    pub(crate) fn parse(input: &str) -> Result<Self, String> {
        let mut terms = Vec::new();
        for raw in input.split_whitespace() {
            let (negated, token) = raw
                .strip_prefix('!')
                .map(|token| (true, token))
                .unwrap_or((false, raw));
            if token.is_empty() {
                return Err("missing condition after !".into());
            }
            terms.push(QueryTerm {
                negated,
                predicate: parse_predicate(token)?,
            });
        }
        Ok(Self { terms })
    }

    pub(crate) fn matches(
        &self,
        process: &ProcessInfo,
        subtree: ResourceAggregate,
        direct_children: usize,
    ) -> bool {
        self.terms.iter().all(|term| {
            let matched = match &term.predicate {
                QueryPredicate::Text { field, value } => {
                    text_value(*field, process).contains(value)
                }
                QueryPredicate::Numeric {
                    field,
                    comparator,
                    value,
                } => comparator.matches(
                    numeric_value(*field, process, subtree, direct_children),
                    *value,
                ),
            };
            matched != term.negated
        })
    }
}

fn parse_predicate(token: &str) -> Result<QueryPredicate, String> {
    if let Some((field, value)) = token.split_once(':') {
        let normalized = field.to_ascii_lowercase();
        let text_field = match normalized.as_str() {
            "name" => Some(TextField::Name),
            "cmd" | "command" => Some(TextField::Command),
            "path" | "exe" => Some(TextField::Path),
            "user" => Some(TextField::User),
            "state" | "status" => Some(TextField::State),
            _ => None,
        };
        if let Some(field) = text_field {
            if value.is_empty() {
                return Err(format!("{normalized}: requires a value"));
            }
            return Ok(QueryPredicate::Text {
                field,
                value: value.to_lowercase(),
            });
        }
        let numeric_field = match normalized.as_str() {
            "pid" => Some(NumericField::Pid),
            "ppid" => Some(NumericField::ParentPid),
            "children" | "child" => Some(NumericField::Children),
            _ => None,
        };
        if let Some(field) = numeric_field {
            let value = parse_number(value, "integer")?;
            return Ok(QueryPredicate::Numeric {
                field,
                comparator: Comparator::Equal,
                value,
            });
        }
    }

    if let Some((field, comparator, value)) =
        split_comparison(token).and_then(|(field, comparator, value)| {
            numeric_field(field).map(|field| (field, comparator, value))
        })
    {
        return Ok(QueryPredicate::Numeric {
            field,
            comparator,
            value: parse_field_value(field, value)?,
        });
    }

    Ok(QueryPredicate::Text {
        field: TextField::Any,
        value: token.to_lowercase(),
    })
}

fn split_comparison(token: &str) -> Option<(&str, Comparator, &str)> {
    for (operator, comparator) in [
        (">=", Comparator::GreaterOrEqual),
        ("<=", Comparator::LessOrEqual),
        (">", Comparator::Greater),
        ("<", Comparator::Less),
        ("=", Comparator::Equal),
    ] {
        if let Some((field, value)) = token.split_once(operator) {
            return Some((field, comparator, value));
        }
    }
    None
}

fn numeric_field(field: &str) -> Option<NumericField> {
    match field.to_ascii_lowercase().as_str() {
        "pid" => Some(NumericField::Pid),
        "ppid" => Some(NumericField::ParentPid),
        "children" | "child" => Some(NumericField::Children),
        "cpu" => Some(NumericField::Cpu),
        "mem" | "memory" => Some(NumericField::Memory),
        "read" => Some(NumericField::ReadRate),
        "write" => Some(NumericField::WriteRate),
        "age" | "runtime" => Some(NumericField::Age),
        "tree.procs" | "tree.processes" => Some(NumericField::TreeProcesses),
        "tree.cpu" => Some(NumericField::TreeCpu),
        "tree.mem" | "tree.memory" => Some(NumericField::TreeMemory),
        "tree.read" => Some(NumericField::TreeReadRate),
        "tree.write" => Some(NumericField::TreeWriteRate),
        _ => None,
    }
}

fn parse_field_value(field: NumericField, value: &str) -> Result<f64, String> {
    match field {
        NumericField::Cpu | NumericField::TreeCpu => {
            parse_number(value.trim_end_matches('%'), "CPU percent")
        }
        NumericField::Memory
        | NumericField::ReadRate
        | NumericField::WriteRate
        | NumericField::TreeMemory
        | NumericField::TreeReadRate
        | NumericField::TreeWriteRate => parse_bytes(value),
        NumericField::Age => parse_duration(value),
        NumericField::Pid
        | NumericField::ParentPid
        | NumericField::Children
        | NumericField::TreeProcesses => parse_number(value, "integer"),
    }
}

fn parse_number(value: &str, label: &str) -> Result<f64, String> {
    if value.is_empty() {
        return Err(format!("missing {label} value"));
    }
    let parsed = value
        .parse::<f64>()
        .map_err(|_| format!("invalid {label}: {value}"))?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err(format!("invalid {label}: {value}"));
    }
    Ok(parsed)
}

fn parse_bytes(value: &str) -> Result<f64, String> {
    let normalized = value.to_ascii_lowercase();
    let normalized = normalized.strip_suffix("/s").unwrap_or(&normalized);
    let units = [
        ("tib", 1024_f64.powi(4)),
        ("tb", 1024_f64.powi(4)),
        ("t", 1024_f64.powi(4)),
        ("gib", 1024_f64.powi(3)),
        ("gb", 1024_f64.powi(3)),
        ("g", 1024_f64.powi(3)),
        ("mib", 1024_f64.powi(2)),
        ("mb", 1024_f64.powi(2)),
        ("m", 1024_f64.powi(2)),
        ("kib", 1024_f64),
        ("kb", 1024_f64),
        ("k", 1024_f64),
        ("b", 1_f64),
    ];
    for (suffix, multiplier) in units {
        if let Some(number) = normalized.strip_suffix(suffix) {
            return parse_number(number, "byte").map(|number| number * multiplier);
        }
    }
    parse_number(normalized, "byte")
}

fn parse_duration(value: &str) -> Result<f64, String> {
    let normalized = value.to_ascii_lowercase();
    let units = [
        ("d", 86_400_f64),
        ("h", 3_600_f64),
        ("m", 60_f64),
        ("s", 1_f64),
    ];
    for (suffix, multiplier) in units {
        if let Some(number) = normalized.strip_suffix(suffix) {
            return parse_number(number, "duration").map(|number| number * multiplier);
        }
    }
    parse_number(&normalized, "duration")
}

fn text_value(field: TextField, process: &ProcessInfo) -> String {
    match field {
        TextField::Any => format!(
            "{} {} {} {} {} {} {}",
            process.name,
            process.command,
            process.executable,
            process.user,
            process.cwd,
            process.status,
            process.pid
        ),
        TextField::Name => process.name.clone(),
        TextField::Command => process.command.clone(),
        TextField::Path => process_path(process),
        TextField::User => process.user.clone(),
        TextField::State => process.status.clone(),
    }
    .to_lowercase()
}

fn numeric_value(
    field: NumericField,
    process: &ProcessInfo,
    subtree: ResourceAggregate,
    direct_children: usize,
) -> f64 {
    match field {
        NumericField::Pid => process.pid.as_u32() as f64,
        NumericField::ParentPid => process.parent.map(Pid::as_u32).unwrap_or(0) as f64,
        NumericField::Children => direct_children as f64,
        NumericField::Cpu => process.cpu as f64,
        NumericField::Memory => process.memory as f64,
        NumericField::ReadRate => process.read_rate as f64,
        NumericField::WriteRate => process.write_rate as f64,
        NumericField::Age => process.runtime as f64,
        NumericField::TreeProcesses => subtree.process_count as f64,
        NumericField::TreeCpu => subtree.cpu as f64,
        NumericField::TreeMemory => subtree.memory as f64,
        NumericField::TreeReadRate => subtree.read_rate as f64,
        NumericField::TreeWriteRate => subtree.write_rate as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process() -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(42),
            parent: Some(Pid::from_u32(1)),
            name: "api-server".into(),
            command: "/opt/api-server --port 8080".into(),
            executable: "/opt/api-server".into(),
            user: "deploy".into(),
            cwd: "/srv/api".into(),
            cpu: 25.0,
            memory: 768 * 1024 * 1024,
            read_rate: 2 * 1024 * 1024,
            write_rate: 256 * 1024,
            start_time: 100,
            runtime: 7_200,
            status: "Sleep".into(),
        }
    }

    fn subtree() -> ResourceAggregate {
        ResourceAggregate {
            cpu: 60.0,
            memory: 3 * 1024 * 1024 * 1024,
            read_rate: 5 * 1024 * 1024,
            write_rate: 1024 * 1024,
            process_count: 4,
        }
    }

    #[test]
    fn plain_terms_preserve_the_original_case_insensitive_search() {
        let query = ProcessQuery::parse("API 8080").expect("parse plain query");
        assert!(query.matches(&process(), subtree(), 3));
        assert!(
            !ProcessQuery::parse("worker")
                .expect("parse plain query")
                .matches(&process(), subtree(), 3)
        );
    }

    #[test]
    fn combines_fields_metrics_units_subtrees_and_negation() {
        let query = ProcessQuery::parse(
            "user:deploy state:sleep cpu>=20 mem>500m read>1mb/s age>=1h children:3 tree.mem>2g !name:worker",
        )
        .expect("parse structured query");
        assert!(query.matches(&process(), subtree(), 3));
        assert!(
            !ProcessQuery::parse("tree.cpu>80")
                .expect("parse tree query")
                .matches(&process(), subtree(), 3)
        );
        assert!(
            !ProcessQuery::parse("!user:deploy")
                .expect("parse negation")
                .matches(&process(), subtree(), 3)
        );
    }

    #[test]
    fn reports_errors_only_for_recognized_structured_conditions() {
        assert_eq!(
            ProcessQuery::parse("mem>large").expect_err("invalid bytes"),
            "invalid byte: large"
        );
        assert!(ProcessQuery::parse("user:").is_err());
        assert!(ProcessQuery::parse("cpu>NaN").is_err());
        assert!(ProcessQuery::parse("age>-1h").is_err());
        assert!(ProcessQuery::parse("https://example.com").is_ok());
    }
}
