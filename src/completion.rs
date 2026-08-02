use crate::cli::CompletionShell;

pub(crate) fn completion_script(shell: CompletionShell) -> &'static str {
    match shell {
        CompletionShell::Bash => BASH_COMPLETION,
        CompletionShell::Zsh => ZSH_COMPLETION,
        CompletionShell::Fish => FISH_COMPLETION,
    }
}

const BASH_COMPLETION: &str = r#"# psmore bash completion
_psmore_completion() {
    local cur prev cmd words
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd="${COMP_WORDS[1]}"

    case "$prev" in
        --expect) words="none any" ;;
        --protocol)
            if [[ "$cmd" == "listen" || "$cmd" == "net" ]]; then words="any tcp udp unix"; else words="any tcp udp"; fi ;;
        --depth) words="all" ;;
        --limit) if [[ "$cmd" == "logs" || "$cmd" == "explain" ]]; then words=""; else words="all"; fi ;;
        --by)
            if [[ "$cmd" == "cgroup" ]]; then words="cpu memory pressure processes"; else words="cpu memory read write"; fi ;;
        --scope)
            if [[ "$cmd" == "logs" || "$cmd" == "explain" ]]; then words="auto process service"; else words="process tree"; fi ;;
        --priority) words="error warning info debug" ;;
        --state) words="ESTABLISHED LISTEN TIME_WAIT CLOSE_WAIT SYN_SENT SYN_RECV CONNECTED CONNECTING BOUND OPEN" ;;
        --fail-on)
            if [[ "$cmd" == "diff" ]]; then words="never regression"; else words="never warning critical"; fi ;;
        --output) compopt -o default; return ;;
        completion) words="bash zsh fish" ;;
        *) words="" ;;
    esac
    if [[ -n "$words" ]]; then
        COMPREPLY=( $(compgen -W "$words" -- "$cur") )
        return
    fi

    if (( COMP_CWORD == 1 )); then
        words="check inspect memory explain exe stale service logs port listen net tree watch trace run deleted file fd top oom cgroup doctor diff completion --table --json --query --no-tips --sample-ms --redact --help --version"
        COMPREPLY=( $(compgen -W "$words" -- "$cur") )
        return
    fi

    if [[ "$cmd" == "file" && "$cur" != -* ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
        return
    fi

    case "$cmd" in
        check) words="--expect --wait --interval-ms --stable --table --json --quiet --sample-ms --help --version" ;;
        inspect) words="--table --json --sample-ms --help --version" ;;
        memory) words="--limit --table --json --help --version" ;;
        explain) words="--scope --since --priority --limit --no-logs --no-hash --sample-ms --table --json --output --force --help --version" ;;
        exe) words="--table --json --no-hash --help --version" ;;
        stale) words="--query --limit --table --json --expect --quiet --sample-ms --help --version" ;;
        service) words="--table --json --help --version" ;;
        logs) words="--scope --since --priority --limit --table --json --help --version" ;;
        port) words="--protocol --all --table --json --expect --quiet --help --version" ;;
        listen) words="--query --protocol --exposed --limit --table --json --expect --quiet --help --version" ;;
        tree) words="--depth --table --json --sample-ms --help --version" ;;
        watch) words="--query --table --jsonl --interval-ms --count --help --version" ;;
        trace) words="--table --jsonl --interval-ms --count --help --version" ;;
        run) words="--table --json --interval-ms --linger-ms --output --force -- --help --version" ;;
        deleted) words="--min-size --table --json --expect --quiet --help --version" ;;
        file) words="--recursive --limit --table --json --expect --quiet --help --version" ;;
        fd) words="--min-count --min-percent --limit --table --json --expect --quiet --help --version" ;;
        top) words="--query --by --scope --limit --table --json --sample-ms --help --version" ;;
        oom) words="--query --min-score --limit --table --json --expect --quiet --sample-ms --help --version" ;;
        cgroup) words="--query --by --limit --table --json --sample-ms --help --version" ;;
        net) words="--query --protocol --connected --state --limit --table --json --expect --quiet --help --version" ;;
        doctor) words="--query --deep --limit --table --json --output --force --fail-on --quiet --sample-ms --help --version" ;;
        diff) words="--table --json --output --force --fail-on --quiet --help --version" ;;
        completion) words="bash zsh fish --help --version" ;;
        *) words="--query --no-tips --table --json --sample-ms --help --version" ;;
    esac
    words="$words --redact"
    COMPREPLY=( $(compgen -W "$words" -- "$cur") )
}
complete -F _psmore_completion psmore
"#;

const ZSH_COMPLETION: &str = r#"#compdef psmore
# psmore zsh completion
_psmore() {
  local cmd prev
  local -a commands options
  commands=(
    'check:evaluate a process-query health gate'
    'inspect:deep inspection for one process'
    'memory:attribute one process memory and mapped regions'
    'explain:build a prioritized process evidence dossier'
    'exe:verify a process executable image and provenance'
    'stale:find Linux processes holding obsolete executables'
    'service:resolve a PID to systemd or launchd context'
    'logs:read bounded native logs for a process or service'
    'port:find the owner of one local port'
    'listen:inventory listeners and exposure'
    'net:search all sockets peer endpoints and owners'
    'tree:print process ancestor and descendant context'
    'watch:stream lifecycle and query events'
    'trace:record process and subtree resource samples'
    'run:launch a command and profile its process subtree'
    'deleted:find deleted files still held open'
    'file:find processes using a file or directory'
    'fd:rank file-descriptor pressure'
    'top:rank CPU memory and disk I/O hotspots'
    'oom:diagnose Linux memory pressure and OOM priority'
    'cgroup:inventory Linux systemd and container boundaries'
    'doctor:run conservative host and process triage'
    'diff:compare process snapshots or doctor reports'
    'completion:generate shell completion'
    '--table:print a table snapshot and exit'
    '--json:print a JSON snapshot and exit'
    '--query:filter the TUI or snapshot'
    '--no-tips:skip the startup help or tip for this TUI run'
    '--sample-ms:set the snapshot sampling interval'
    '--redact:mask common secret values in command lines'
    '--help:print global help'
    '--version:print version'
  )

  if (( CURRENT == 2 )); then
    _describe 'psmore command' commands
    return
  fi

  cmd="$words[2]"
  prev="$words[CURRENT-1]"
  case "$prev" in
    --expect) _values 'expectation' none any; return ;;
    --protocol)
      if [[ "$cmd" == listen || "$cmd" == net ]]; then _values 'protocol' any tcp udp unix
      else _values 'protocol' any tcp udp; fi
      return ;;
    --depth) _values 'value' all; return ;;
    --limit)
      if [[ "$cmd" != logs && "$cmd" != explain ]]; then _values 'value' all; return; fi ;;
    --by)
      if [[ "$cmd" == cgroup ]]; then _values 'metric' cpu memory pressure processes
      else _values 'metric' cpu memory read write; fi
      return ;;
    --fail-on)
      if [[ "$cmd" == diff ]]; then _values 'policy' never regression
      else _values 'severity' never warning critical; fi
      return ;;
    --scope)
      if [[ "$cmd" == logs || "$cmd" == explain ]]; then _values 'scope' auto process service
      else _values 'scope' process tree; fi
      return ;;
    --priority) _values 'priority' error warning info debug; return ;;
  esac
  if [[ "$cmd" == completion && CURRENT == 3 ]]; then
    _values 'shell' bash zsh fish
    return
  fi

  case "$cmd" in
    check) options=( '--expect[none or any]:mode:(none any)' '--wait[retry until policy passes]:duration:' '--interval-ms[evaluation cadence]:milliseconds:' '--stable[required consecutive passes]:samples:' '--table[table output]' '--json[JSON output]' '--quiet[suppress output]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    inspect) options=( '--table[table output]' '--json[JSON output]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    memory) options=( '--limit[maximum rows per evidence section]:rows:(all)' '--table[table output]' '--json[JSON output]' ) ;;
    explain) options=( '--scope[process or service log boundary]:scope:(auto process service)' '--since[recent log window]:duration:' '--priority[maximum log verbosity]:priority:(error warning info debug)' '--limit[newest log entries]:rows:' '--no-logs[skip native logs]' '--no-hash[skip SHA-256 reads]' '--sample-ms[sampling milliseconds]:milliseconds:' '--table[table output]' '--json[JSON output]' '--output[atomically write private JSON]:file:_files' '--force[replace an existing output file]' ) ;;
    exe) options=( '--table[table output]' '--json[JSON output]' '--no-hash[skip SHA-256 reads]' ) ;;
    stale) options=( '--query[process query]:query:' '--limit[maximum stale processes]:rows:(all)' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    service) options=( '--table[table output]' '--json[JSON output]' ) ;;
    logs) options=( '--scope[process or service boundary]:scope:(auto process service)' '--since[recent time window]:duration:' '--priority[maximum verbosity]:priority:(error warning info debug)' '--limit[newest entries]:rows:' '--table[table output]' '--json[JSON output]' ) ;;
    port) options=( '--protocol[protocol]:protocol:(any tcp udp)' '--all[include connections]' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' ) ;;
    listen) options=( '--query[filter text]:filter:' '--protocol[protocol]:protocol:(any tcp udp unix)' '--exposed[non-loopback binds only]' '--limit[maximum rows]:rows:(all)' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' ) ;;
    net) options=( '--query[filter text]:filter:' '--protocol[protocol]:protocol:(any tcp udp unix)' '--connected[peer or connected sockets only]' '--state[exact socket state]:state:(ESTABLISHED LISTEN TIME_WAIT CLOSE_WAIT SYN_SENT SYN_RECV CONNECTED CONNECTING BOUND OPEN)' '--limit[maximum rows]:rows:(all)' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' ) ;;
    tree) options=( '--depth[descendant depth]:depth:(all)' '--table[table output]' '--json[JSON output]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    watch) options=( '--query[process query]:query:' '--table[table stream]' '--jsonl[JSONL stream]' '--interval-ms[refresh milliseconds]:milliseconds:' '--count[refresh count]:count:' ) ;;
    trace) options=( '--table[table stream]' '--jsonl[JSONL stream]' '--interval-ms[refresh milliseconds]:milliseconds:' '--count[sample count]:count:' ) ;;
    run) options=( '--table[table report on stderr]' '--json[JSON report on stderr]' '--interval-ms[sampling milliseconds]:milliseconds:' '--linger-ms[post-exit descendant grace]:milliseconds:' '--output[atomically write private JSON]:file:_files' '--force[replace an existing output file]' ) ;;
    deleted) options=( '--min-size[minimum reclaimable size]:size:' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' ) ;;
    file) options=( '--recursive[match all descendants]' '--limit[maximum evidence rows]:rows:(all)' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' ) ;;
    fd) options=( '--min-count[minimum descriptors]:count:' '--min-percent[minimum utilization]:percent:' '--limit[maximum rows]:rows:(all)' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' ) ;;
    top) options=( '--query[process query]:query:' '--by[ranking metric]:metric:(cpu memory read write)' '--scope[ranking scope]:scope:(process tree)' '--limit[maximum rows]:rows:(all)' '--table[table output]' '--json[JSON output]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    oom) options=( '--query[process query]:query:' '--min-score[minimum kernel OOM score]:score:' '--limit[maximum candidates]:rows:(all)' '--table[table output]' '--json[JSON output]' '--expect[policy]:mode:(none any)' '--quiet[suppress output]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    cgroup) options=( '--query[boundary or process filter]:filter:' '--by[ranking metric]:metric:(cpu memory pressure processes)' '--limit[maximum groups]:rows:(all)' '--table[table output]' '--json[JSON output]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    doctor) options=( '--query[scope quick process signals and hotspots]:query:' '--deep[scan exposure fd deleted files and Linux OOM]' '--limit[maximum rows per section]:rows:(all)' '--table[table output]' '--json[JSON output]' '--output[atomically write private JSON]:file:_files' '--force[replace an existing output file]' '--fail-on[exit threshold]:severity:(never warning critical)' '--quiet[suppress stdout]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
    diff) options=( '--table[table output]' '--json[JSON output]' '--output[atomically write private JSON]:file:_files' '--force[replace an existing output file]' '--fail-on[exit for doctor regression]:policy:(never regression)' '--quiet[suppress stdout]' ) ;;
    completion) options=() ;;
    *) options=( '--query[process query]:query:' '--no-tips[skip startup guidance for this TUI run]' '--table[table snapshot]' '--json[JSON snapshot]' '--sample-ms[sampling milliseconds]:milliseconds:' ) ;;
  esac
  options+=( '--redact[mask common secret values in command lines]' '-h[print help]' '--help[print help]' '-V[print version]' '--version[print version]' )
  _arguments -s $options '*:argument:_files'
}
compdef _psmore psmore
"#;

const FISH_COMPLETION: &str = r#"# psmore fish completion
complete -c psmore -f
complete -c psmore -n '__fish_use_subcommand' -a check -d 'Evaluate a process-query health gate'
complete -c psmore -n '__fish_use_subcommand' -a inspect -d 'Deep inspection for one process'
complete -c psmore -n '__fish_use_subcommand' -a memory -d 'Attribute one process memory and mapped regions'
complete -c psmore -n '__fish_use_subcommand' -a explain -d 'Build a prioritized process evidence dossier'
complete -c psmore -n '__fish_use_subcommand' -a exe -d 'Verify a process executable image and provenance'
complete -c psmore -n '__fish_use_subcommand' -a stale -d 'Find Linux processes holding obsolete executables'
complete -c psmore -n '__fish_use_subcommand' -a service -d 'Resolve a PID to systemd or launchd context'
complete -c psmore -n '__fish_use_subcommand' -a logs -d 'Read bounded native logs for a process or service'
complete -c psmore -n '__fish_use_subcommand' -a port -d 'Find the owner of one local port'
complete -c psmore -n '__fish_use_subcommand' -a listen -d 'Inventory listeners and exposure'
complete -c psmore -n '__fish_use_subcommand' -a net -d 'Search all sockets, peers, and owners'
complete -c psmore -n '__fish_use_subcommand' -a tree -d 'Print process relationship context'
complete -c psmore -n '__fish_use_subcommand' -a watch -d 'Stream lifecycle and query events'
complete -c psmore -n '__fish_use_subcommand' -a trace -d 'Record process and subtree samples'
complete -c psmore -n '__fish_use_subcommand' -a run -d 'Launch and profile a complete process subtree'
complete -c psmore -n '__fish_use_subcommand' -a deleted -d 'Find deleted files still held open'
complete -c psmore -n '__fish_use_subcommand' -a file -d 'Find processes using a file or directory'
complete -c psmore -n '__fish_use_subcommand' -a fd -d 'Rank file-descriptor pressure'
complete -c psmore -n '__fish_use_subcommand' -a top -d 'Rank CPU, memory, and disk I/O hotspots'
complete -c psmore -n '__fish_use_subcommand' -a oom -d 'Diagnose Linux memory pressure and OOM priority'
complete -c psmore -n '__fish_use_subcommand' -a cgroup -d 'Inventory Linux systemd and container boundaries'
complete -c psmore -n '__fish_use_subcommand' -a doctor -d 'Run conservative host and process triage'
complete -c psmore -n '__fish_use_subcommand' -a diff -d 'Compare snapshots or doctor reports'
complete -c psmore -n '__fish_use_subcommand' -a completion -d 'Generate shell completion'

complete -c psmore -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c psmore -n 'not __fish_seen_subcommand_from check inspect memory explain exe stale service logs port listen net tree watch trace run deleted file fd top oom cgroup doctor diff completion' -s q -l query -r -d 'Initial TUI or snapshot query'
complete -c psmore -n 'not __fish_seen_subcommand_from check inspect memory explain exe stale service logs port listen net tree watch trace run deleted file fd top oom cgroup doctor diff completion' -l no-tips -d 'Skip startup guidance for this TUI run'
complete -c psmore -n 'not __fish_seen_subcommand_from check inspect memory explain exe stale service logs port listen net tree watch trace run deleted file fd top oom cgroup doctor diff completion' -l table -d 'Print table snapshot'
complete -c psmore -n 'not __fish_seen_subcommand_from check inspect memory explain exe stale service logs port listen net tree watch trace run deleted file fd top oom cgroup doctor diff completion' -l json -d 'Print JSON snapshot'
complete -c psmore -n 'not __fish_seen_subcommand_from check inspect memory explain exe stale service logs port listen net tree watch trace run deleted file fd top oom cgroup doctor diff completion' -l sample-ms -r -d 'Sampling milliseconds'
complete -c psmore -n '__fish_seen_subcommand_from check stale port listen net deleted file fd oom' -l expect -xa 'none any'
complete -c psmore -n '__fish_seen_subcommand_from check' -l wait -r -d 'Retry until policy passes or duration expires'
complete -c psmore -n '__fish_seen_subcommand_from check' -l interval-ms -r -d 'Evaluation cadence while waiting'
complete -c psmore -n '__fish_seen_subcommand_from check' -l stable -r -d 'Required consecutive passing evaluations'
complete -c psmore -n '__fish_seen_subcommand_from port' -l protocol -xa 'any tcp udp'
complete -c psmore -n '__fish_seen_subcommand_from listen' -l protocol -xa 'any tcp udp unix'
complete -c psmore -n '__fish_seen_subcommand_from net' -l protocol -xa 'any tcp udp unix'
complete -c psmore -n '__fish_seen_subcommand_from net' -l connected -d 'Peer or connected sockets only'
complete -c psmore -n '__fish_seen_subcommand_from net' -l state -xa 'ESTABLISHED LISTEN TIME_WAIT CLOSE_WAIT SYN_SENT SYN_RECV CONNECTED CONNECTING BOUND OPEN'
complete -c psmore -n '__fish_seen_subcommand_from stale listen net fd' -l limit -xa all
complete -c psmore -n '__fish_seen_subcommand_from memory' -l limit -xa all
complete -c psmore -n '__fish_seen_subcommand_from top' -l by -xa 'cpu memory read write'
complete -c psmore -n '__fish_seen_subcommand_from top' -l scope -xa 'process tree'
complete -c psmore -n '__fish_seen_subcommand_from logs explain' -l scope -xa 'auto process service'
complete -c psmore -n '__fish_seen_subcommand_from logs explain' -l since -r -d 'Recent time window such as 15m or 2h'
complete -c psmore -n '__fish_seen_subcommand_from logs explain' -l priority -xa 'error warning info debug'
complete -c psmore -n '__fish_seen_subcommand_from logs explain' -l limit -r
complete -c psmore -n '__fish_seen_subcommand_from explain' -l no-logs -d 'Skip native logs'
complete -c psmore -n '__fish_seen_subcommand_from explain' -l no-hash -d 'Skip SHA-256 reads'
complete -c psmore -n '__fish_seen_subcommand_from explain' -l output -r -F -d 'Atomically write private JSON'
complete -c psmore -n '__fish_seen_subcommand_from explain' -l force -d 'Replace an existing output file'
complete -c psmore -n '__fish_seen_subcommand_from cgroup' -l by -xa 'cpu memory pressure processes'
complete -c psmore -n '__fish_seen_subcommand_from cgroup' -l limit -xa all
complete -c psmore -n '__fish_seen_subcommand_from top' -l limit -xa all
complete -c psmore -n '__fish_seen_subcommand_from oom' -l min-score -r
complete -c psmore -n '__fish_seen_subcommand_from oom' -l limit -xa all
complete -c psmore -n '__fish_seen_subcommand_from doctor' -l limit -xa all
complete -c psmore -n '__fish_seen_subcommand_from doctor' -l fail-on -xa 'never warning critical'
complete -c psmore -n '__fish_seen_subcommand_from doctor' -l deep -d 'Scan exposure, FD pressure, deleted files, and Linux OOM'
complete -c psmore -n '__fish_seen_subcommand_from doctor' -l output -r -F -d 'Atomically write private JSON'
complete -c psmore -n '__fish_seen_subcommand_from doctor' -l force -d 'Replace an existing output file'
complete -c psmore -n '__fish_seen_subcommand_from diff' -l fail-on -xa 'never regression'
complete -c psmore -n '__fish_seen_subcommand_from diff' -l output -r -F -d 'Atomically write private JSON'
complete -c psmore -n '__fish_seen_subcommand_from diff' -l force -d 'Replace an existing output file'
complete -c psmore -n '__fish_seen_subcommand_from tree' -l depth -xa all
complete -c psmore -n '__fish_seen_subcommand_from port' -l all -d 'Include non-listening connections'
complete -c psmore -n '__fish_seen_subcommand_from listen' -l exposed -d 'Wildcard and non-loopback binds only'
complete -c psmore -n '__fish_seen_subcommand_from watch trace' -l interval-ms -r
complete -c psmore -n '__fish_seen_subcommand_from watch trace' -l count -r
complete -c psmore -n '__fish_seen_subcommand_from run' -l interval-ms -r -d 'Sampling milliseconds'
complete -c psmore -n '__fish_seen_subcommand_from run' -l linger-ms -r -d 'Post-exit descendant grace milliseconds'
complete -c psmore -n '__fish_seen_subcommand_from run' -l output -r -F -d 'Atomically write private JSON'
complete -c psmore -n '__fish_seen_subcommand_from run' -l force -d 'Replace an existing output file'
complete -c psmore -n '__fish_seen_subcommand_from exe' -l no-hash -d 'Skip SHA-256 reads'
complete -c psmore -n '__fish_seen_subcommand_from inspect explain stale tree check top oom cgroup doctor' -l sample-ms -r
complete -c psmore -n '__fish_seen_subcommand_from deleted' -l min-size -r
complete -c psmore -n '__fish_seen_subcommand_from file' -l recursive -d 'Match the path and all descendants'
complete -c psmore -n '__fish_seen_subcommand_from file' -l limit -xa all
complete -c psmore -n '__fish_seen_subcommand_from file' -F
complete -c psmore -n '__fish_seen_subcommand_from fd' -l min-count -r
complete -c psmore -n '__fish_seen_subcommand_from fd' -l min-percent -r
complete -c psmore -n '__fish_seen_subcommand_from stale listen net watch top oom cgroup doctor' -s q -l query -r
complete -c psmore -n '__fish_seen_subcommand_from check inspect memory explain exe stale service logs port listen net tree run deleted file fd top oom cgroup doctor diff' -l table
complete -c psmore -n '__fish_seen_subcommand_from check inspect memory explain exe stale service logs port listen net tree run deleted file fd top oom cgroup doctor diff' -l json
complete -c psmore -n '__fish_seen_subcommand_from watch trace' -l jsonl
complete -c psmore -n '__fish_seen_subcommand_from check stale port listen net deleted file fd oom doctor diff' -l quiet
complete -c psmore -l redact -d 'Mask common secret values in command lines'
complete -c psmore -s h -l help -d 'Print help'
complete -c psmore -s V -l version -d 'Print version'
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_completion_script_covers_every_subcommand_and_enum_values() {
        let commands = [
            "check",
            "inspect",
            "memory",
            "explain",
            "exe",
            "stale",
            "service",
            "logs",
            "port",
            "listen",
            "net",
            "tree",
            "watch",
            "trace",
            "run",
            "deleted",
            "file",
            "fd",
            "top",
            "oom",
            "cgroup",
            "doctor",
            "diff",
            "completion",
        ];
        for shell in [
            CompletionShell::Bash,
            CompletionShell::Zsh,
            CompletionShell::Fish,
        ] {
            let script = completion_script(shell);
            for command in commands {
                assert!(
                    script.contains(command),
                    "{} completion is missing {command}",
                    shell.label()
                );
            }
            for value in [
                "none", "any", "tcp", "udp", "unix", "all", "auto", "service", "error", "debug",
            ] {
                assert!(
                    script.contains(value),
                    "{} completion is missing {value}",
                    shell.label()
                );
            }
            for value in [
                "cpu",
                "memory",
                "read",
                "write",
                "process",
                "tree",
                "pressure",
                "processes",
            ] {
                assert!(
                    script.contains(value),
                    "{} completion is missing {value}",
                    shell.label()
                );
            }
            for value in ["ESTABLISHED", "TIME_WAIT", "CONNECTED"] {
                assert!(
                    script.contains(value),
                    "{} completion is missing {value}",
                    shell.label()
                );
            }
            for value in ["never", "warning", "critical", "regression"] {
                assert!(
                    script.contains(value),
                    "{} completion is missing {value}",
                    shell.label()
                );
            }
            assert!(
                script.contains("--redact") || script.contains("-l redact"),
                "{} completion is missing --redact",
                shell.label()
            );
            assert!(
                (script.contains("--output") || script.contains("-l output"))
                    && (script.contains("--force") || script.contains("-l force")),
                "{} completion is missing secure output options",
                shell.label()
            );
            assert!(
                script.contains("--deep") || script.contains("-l deep"),
                "{} completion is missing doctor --deep",
                shell.label()
            );
            assert!(
                (script.contains("--wait") || script.contains("-l wait"))
                    && (script.contains("--stable") || script.contains("-l stable")),
                "{} completion is missing check convergence options",
                shell.label()
            );
            assert!(
                script.contains("--recursive") || script.contains("-l recursive"),
                "{} completion is missing file --recursive",
                shell.label()
            );
            assert!(
                script.contains("--no-hash") || script.contains("-l no-hash"),
                "{} completion is missing exe --no-hash",
                shell.label()
            );
            match shell {
                CompletionShell::Bash => assert!(script.contains("compgen -f")),
                CompletionShell::Zsh => assert!(script.contains("_files")),
                CompletionShell::Fish => assert!(script.contains("file' -F")),
            }
        }
    }
}
