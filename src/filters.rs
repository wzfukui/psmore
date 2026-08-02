use serde::{Deserialize, Serialize};

use crate::{
    model::{ProcessInfo, ResourceAggregate},
    query::ProcessQuery,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FilterAction {
    Include,
    Exclude,
}

impl FilterAction {
    pub(crate) fn toggle(self) -> Self {
        match self {
            Self::Include => Self::Exclude,
            Self::Exclude => Self::Include,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ProcessFilterRule {
    pub(crate) action: FilterAction,
    pub(crate) expression: String,
    #[serde(default = "enabled_by_default")]
    pub(crate) enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

pub(crate) struct CompiledProcessFilters {
    includes: Vec<ProcessQuery>,
    excludes: Vec<ProcessQuery>,
}

impl CompiledProcessFilters {
    pub(crate) fn compile(rules: &[ProcessFilterRule]) -> Result<Self, String> {
        let mut includes = Vec::new();
        let mut excludes = Vec::new();
        for (index, rule) in rules.iter().enumerate().filter(|(_, rule)| rule.enabled) {
            let expression = rule.expression.trim();
            if expression.is_empty() {
                return Err(format!("filter {} is empty", index + 1));
            }
            let query = ProcessQuery::parse(expression)
                .map_err(|error| format!("filter {}: {error}", index + 1))?;
            match rule.action {
                FilterAction::Include => includes.push(query),
                FilterAction::Exclude => excludes.push(query),
            }
        }
        Ok(Self { includes, excludes })
    }

    pub(crate) fn matches(
        &self,
        process: &ProcessInfo,
        subtree: ResourceAggregate,
        direct_children: usize,
    ) -> bool {
        let included = self.includes.is_empty()
            || self
                .includes
                .iter()
                .any(|query| query.matches(process, subtree, direct_children));
        included
            && !self
                .excludes
                .iter()
                .any(|query| query.matches(process, subtree, direct_children))
    }
}

#[cfg(test)]
mod tests {
    use sysinfo::Pid;

    use super::*;

    fn process(name: &str, path: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(42),
            parent: Some(Pid::from_u32(1)),
            name: name.into(),
            command: path.into(),
            executable: path.into(),
            user: "joe".into(),
            cwd: "/tmp".into(),
            cpu: 0.0,
            memory: 0,
            read_rate: 0,
            write_rate: 0,
            start_time: 1,
            runtime: 1,
            status: "Sleep".into(),
        }
    }

    fn rule(action: FilterAction, expression: &str) -> ProcessFilterRule {
        ProcessFilterRule {
            action,
            expression: expression.into(),
            enabled: true,
        }
    }

    #[test]
    fn include_rules_are_or_and_exclude_rules_override_them() {
        let rules = vec![
            rule(FilterAction::Include, "path:/Applications"),
            rule(FilterAction::Include, "path:/opt/homebrew"),
            rule(FilterAction::Exclude, "name~^(Helper|Updater)$"),
        ];
        let filters = CompiledProcessFilters::compile(&rules).unwrap();
        let resources = ResourceAggregate::default();

        assert!(filters.matches(
            &process(
                "ChatGPT",
                "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"
            ),
            resources,
            0
        ));
        assert!(filters.matches(&process("node", "/opt/homebrew/bin/node"), resources, 0));
        assert!(!filters.matches(&process("launchd", "/sbin/launchd"), resources, 0));
        assert!(!filters.matches(
            &process("Helper", "/Applications/Example.app/Contents/MacOS/Helper"),
            resources,
            0
        ));
    }

    #[test]
    fn disabled_and_invalid_rules_are_handled_explicitly() {
        let disabled = ProcessFilterRule {
            action: FilterAction::Exclude,
            expression: "path~[".into(),
            enabled: false,
        };
        assert!(CompiledProcessFilters::compile(&[disabled]).is_ok());
        assert!(CompiledProcessFilters::compile(&[rule(FilterAction::Exclude, "path~[")]).is_err());
    }
}
