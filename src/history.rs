use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use sysinfo::Pid;

use crate::model::{ProcessInfo, ResourceAggregate};

pub(crate) const DEFAULT_HISTORY_SAMPLES: usize = 90;
const STALE_HISTORY_RETENTION: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct ResourceSample {
    pub(crate) observed_at: Instant,
    pub(crate) own_cpu: f32,
    pub(crate) own_memory: u64,
    pub(crate) subtree_cpu: f32,
    pub(crate) subtree_memory: u64,
    pub(crate) own_read_rate: u64,
    pub(crate) own_write_rate: u64,
    pub(crate) subtree_read_rate: u64,
    pub(crate) subtree_write_rate: u64,
    pub(crate) subtree_processes: usize,
}

#[derive(Clone, Debug)]
struct ProcessSeries {
    start_time: u64,
    name: String,
    samples: VecDeque<ResourceSample>,
}

#[derive(Debug)]
pub(crate) struct ResourceHistory {
    series: HashMap<Pid, ProcessSeries>,
    sample_limit: usize,
}

impl Default for ResourceHistory {
    fn default() -> Self {
        Self::with_sample_limit(DEFAULT_HISTORY_SAMPLES)
    }
}

impl ResourceHistory {
    pub(crate) fn with_sample_limit(sample_limit: usize) -> Self {
        Self {
            series: HashMap::new(),
            sample_limit: sample_limit.max(1),
        }
    }

    pub(crate) fn record(
        &mut self,
        processes: &HashMap<Pid, ProcessInfo>,
        resources: &HashMap<Pid, ResourceAggregate>,
        observed_at: Instant,
    ) {
        let active: HashSet<Pid> = processes.keys().copied().collect();
        self.series.retain(|pid, series| {
            active.contains(pid)
                || series
                    .samples
                    .back()
                    .map(|sample| {
                        observed_at.saturating_duration_since(sample.observed_at)
                            <= STALE_HISTORY_RETENTION
                    })
                    .unwrap_or(false)
        });

        for process in processes.values() {
            let aggregate = resources.get(&process.pid).copied().unwrap_or_default();
            let identity_changed = self
                .series
                .get(&process.pid)
                .map(|series| {
                    (series.start_time != 0
                        && process.start_time != 0
                        && series.start_time != process.start_time)
                        || (series.start_time == 0
                            && process.start_time == 0
                            && series.name != process.name)
                })
                .unwrap_or(false);
            if identity_changed {
                self.series.remove(&process.pid);
            }

            let series = self
                .series
                .entry(process.pid)
                .or_insert_with(|| ProcessSeries {
                    start_time: process.start_time,
                    name: process.name.clone(),
                    samples: VecDeque::with_capacity(self.sample_limit),
                });
            series.samples.push_back(ResourceSample {
                observed_at,
                own_cpu: process.cpu,
                own_memory: process.memory,
                subtree_cpu: aggregate.cpu,
                subtree_memory: aggregate.memory,
                own_read_rate: process.read_rate,
                own_write_rate: process.write_rate,
                subtree_read_rate: aggregate.read_rate,
                subtree_write_rate: aggregate.write_rate,
                subtree_processes: aggregate.process_count,
            });
            while series.samples.len() > self.sample_limit {
                series.samples.pop_front();
            }
        }
    }

    pub(crate) fn samples(&self, pid: Pid) -> Option<&VecDeque<ResourceSample>> {
        self.series.get(&pid).map(|series| &series.samples)
    }

    pub(crate) fn name(&self, pid: Pid) -> Option<&str> {
        self.series.get(&pid).map(|series| series.name.as_str())
    }
}
