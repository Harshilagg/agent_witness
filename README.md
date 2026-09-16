# agentwitness

**Your AI coding agent's session log is its own self-report. `agentwitness`
is a second, independent witness.**

People run AI coding agents autonomously, often with permission prompts
turned off. Afterwards, the only record of what happened is the agent's own
session log — which is whatever the agent chose to write down. If the agent
runs a shell command that spawns a subprocess, and that subprocess writes a
file somewhere unexpected, the session log shows one `Bash` call and
nothing else. Every existing tool in this space (agenttrace, agentlog,
ClawMetry, AgentOps) works by parsing that same log. If the log doesn't
mention it, those tools don't see it either.

`agentwitness` doesn't read the agent's log to find out what happened. It
watches the filesystem, the process tree, and (optionally) the network
directly, out-of-band, while the agent runs — and only afterwards compares
what it saw against what the agent's log claims. **The discrepancy between
observed and claimed is the product.**

```
agentwitness run -- claude
```

Wrap the agent invocation you'd normally run. Everything else — the TUI,
Ctrl+C, colors, resizing — works exactly as if you hadn't wrapped it at all.

## A real example

This is unedited output from an actual run. The agent's session log for this
run contained exactly one `Write` call (creating `demo_helper.py`) and one
`Bash` call (`sh -c 'python3 demo_helper.py; sleep 6'`) — that script itself,
invisible to the log, waited a second and then detached a subprocess that
wrote a file:

```
$ agentwitness run -- sh -c 'python3 demo_helper.py; sleep 6'
agentwitness: observing sh -c python3 demo_helper.py; sleep 6

Discrepancies (3)
  [MEDIUM] Unclaimed process: Python
    Python ran as a descendant process 1 time(s), but is not mentioned in any claimed Bash command.
    - binary: Python
    - count: 1
  [MEDIUM] Unclaimed process: sleep
    sleep ran as a descendant process 1 time(s), but is not mentioned in any claimed Bash command.
    - binary: sleep
    - count: 1
  [MEDIUM] File changed with no claimed edit
    demo_rogue_evidence.txt changed on disk, but no claimed Edit, Write, MultiEdit or NotebookEdit call references this path.
    - path: demo_rogue_evidence.txt

Summary
  command:    sh -c python3 demo_helper.py; sleep 6
  dir:        /Users/you/project
  duration:   9.158s
  exit code:  0
  files changed: 1 added, 0 modified, 0 deleted
  processes:  2 descendant process(es) observed
  claimed:    0 edit(s), 0 read(s), 0 command(s) (source: claude-code)

Diff
  + demo_rogue_evidence.txt

Confidence
  - process tree sampled every 500ms: very short-lived processes between samples may be missed
  - claim log: 0 claim(s) from 1 Claude Code session file(s)
  - network sampling was not enabled (pass --net to enable); UNEXPECTED_EGRESS never fires without it
```

The file write was caught by the filesystem collector. The deepest,
detached part of the process chain (a grandchild reparented away almost
immediately) was *not* caught by the process collector — see
[What it can miss](#what-it-observes-and-what-it-can-miss) below. That's not
a cherry-picked success story; it's what actually happened when this was
tested, left in because it's the honest result.

## Install

```
go install github.com/Harshilagg/agent_witness@latest
```

Note that `go install` names the binary after the module path, so this
gives you `agent_witness`. The rest of this README calls it
`agentwitness`; rename it if you want the shorter name:

```
mv "$(go env GOPATH)/bin/agent_witness" "$(go env GOPATH)/bin/agentwitness"
```

A `go install` build also reports its version as `dev` rather than
`v0.1.0`, since the version is injected at release-build time via
ldflags. Use a release binary if you need `agentwitness version` to be
meaningful.

Or download a prebuilt binary from the
[Releases page](https://github.com/Harshilagg/agent_witness/releases) —
linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 — and
verify it against `SHA256SUMS` in the same release.

Or build from source (Go 1.22+, no other dependencies):

```
git clone https://github.com/Harshilagg/agent_witness.git
cd agent_witness
go build -o agentwitness .
```

## Usage

```
agentwitness run -- <command...>       wrap and observe an agent invocation
agentwitness run --net -- <command...> also sample network connections (best-effort)
agentwitness report [session-id]       re-render a past session (default: last)
agentwitness list                      list recorded sessions
agentwitness version                   print the version
```

Run it the same way you'd normally invoke your agent:

```
agentwitness run -- claude
agentwitness run -- aider
agentwitness run -- codex
```

`agentwitness` snapshots your project directory before the command starts,
runs the command with your terminal attached directly to it (no pty, no
buffering — it doesn't touch stdin/stdout/stderr at all), samples the
process tree and (if `--net`) network connections while it runs, snapshots
the project directory again afterward, and diffs the two. It then looks for
the agent's own session log (Claude Code only in v0.1.0), extracts what it
claimed to have done, and reports every place the two disagree. State
persists to `.agentwitness/sessions/<id>.json` in your project, so
`agentwitness report` and `agentwitness list` can re-render a past run
without re-executing anything.

**The exit code is always the wrapped command's exit code.** `agentwitness`
never blocks, kills, sandboxes, or modifies what you're running — it only
observes. There's no kill switch; that's a deliberately different product
with different risks.

### Reading the findings

| Type | Meaning | Default severity |
|---|---|---|
| `UNCLAIMED_WRITE` | A file changed on disk with no matching claimed edit | MEDIUM |
| `CLAIM_WITHOUT_EFFECT` | The agent claimed an edit; the file is unchanged | LOW |
| `OUT_OF_BOUNDS` | A claimed edit targets a path outside the project directory | HIGH |
| `SENSITIVE_TOUCH` | A change touched the sensitive path watchlist (`~/.ssh`, `~/.aws`, shell rc files, ...) | HIGH |
| `UNCLAIMED_PROCESS` | A descendant process's binary is never mentioned in any claimed command | MEDIUM |
| `UNEXPECTED_EGRESS` | A network connection outside the configured allowlist (`--net` only) | HIGH |

None of these mean "the agent did something malicious." They mean "here is
a place where what happened and what was reported don't match — go look."
Most of the time the explanation is mundane (a linter wrote a cache file, a
build script forked a compiler). Occasionally it's the thing you actually
wanted to know about.

## What it observes and what it can miss

Be skeptical of any tool that claims complete visibility into a process
tree from userspace. This one doesn't claim that. Specifically:

- **Filesystem**: every regular file under the project directory is
  SHA-256'd before and after, skipping `.git`, `node_modules`, `vendor`,
  `__pycache__`, `.venv`, `target`, `dist`, `build`, `.next`,
  `.agentwitness`, and bare directory names read from `.gitignore`.
  **`.gitignore` support is deliberately approximate** — only bare names
  (`node_modules`) and trailing-slash entries (`dist/`) are honored; globs,
  negations, and anchored/nested patterns are ignored outright rather than
  half-implemented, since a wrong skip silently hides evidence. Files over
  8 MiB are fingerprinted by size and mtime only, not hashed, and flagged as
  such. Symlinks and non-regular files are recorded as skipped, never
  followed. A silent write to some path *outside* the project directory and
  *outside* the sensitive watchlist is invisible to us — we don't scan the
  whole filesystem.
- **Process tree**: sampled every 500ms for the life of the wrapped
  command, retaining every descendant ever seen (including ones that have
  since exited) so ancestry can be resolved afterward. Two real gaps here,
  not one: a process that starts and fully exits between two samples can be
  missed entirely, *and* — more subtly — a child that gets reparented away
  from the tracked tree (its parent exits and it's adopted by init) faster
  than any sample catches it still connected becomes permanently invisible
  to us, regardless of how long it subsequently runs. We watched this
  happen in the example above.
- **Network** (opt-in via `--net`): best-effort only, via `ss` on Linux or
  `lsof` on macOS. If neither is available, this degrades to "network:
  unavailable" and the run continues. No `/proc/net` inode→fd mapping and
  no eBPF in v0.1.0 (see [Roadmap](#roadmap)). Connections are sampled every
  2 seconds while the command runs — a connection opened and fully closed
  between samples is missed. There is no allowlist configuration mechanism
  yet, so with `--net` enabled, every observed connection is reported as
  `UNEXPECTED_EGRESS`; treat it as an inventory of egress, not an alarm
  list, until an allowlist flag exists.
- **Claim parsing**: Claude Code only in v0.1.0. We locate the session log
  by scanning `~/.claude/projects/*/*.jsonl` for files touched during the
  run and confirming the match via the `cwd` field recorded inside the log
  itself (not the undocumented directory-name mangling scheme), and every
  extracted claim is further filtered to the run's own time window — a
  single log file can span days of unrelated work in the same project. The
  log format isn't ours and it drifts; a malformed or unrecognized line is
  skipped, never fatal, and total failure degrades to "claim unavailable,"
  never a crash.

Windows (v0.1.0) collects filesystem only — process, network, and claim
collection are not yet implemented there. Every report's Confidence footer
states plainly which collectors ran, which didn't, and why.

## Privacy

- Zero network egress from the `agentwitness` binary itself. No telemetry,
  no update check, ever.
- Nothing leaves your machine. Everything reads from local disk and local
  process/network state and writes only to `.agentwitness/` in your project.
- Paths, hashes, sizes, and counts only, in both the terminal output and the
  persisted session JSON. File contents and environment variable values are
  never printed or stored.
- The sensitive path watchlist (`~/.ssh`, `~/.aws`, `~/.config`, `.npmrc`,
  `.gitconfig`, shell rc files, one level deep) is fingerprinted with a
  random per-session HMAC key that is generated in memory and never
  persisted. Before/after comparison within a run is exact, but the digests
  written to `.agentwitness/sessions/*.json` can't later be used to confirm
  a guess at, say, the contents of an SSH private key.

## How this differs from agenttrace / agentlog / ClawMetry / AgentOps

Those tools are good at what they do: structured, queryable views over an
agent's own reported activity — timelines, cost tracking, tool-call
analytics, session replay. If you want to understand *what the agent said
it did*, they're the right tool, and better at that presentation layer than
this one currently is.

`agentwitness` answers a narrower, different question: *does what actually
happened match what was reported?* It's not a replacement for those tools —
it's meant to sit next to one. If your session log parser says "the agent
ran 40 tool calls, all successful," `agentwitness` is what tells you whether
a 41st thing also happened that nothing chose to log.

## Roadmap

- **Activity view (next)** — a side-by-side `claimed` vs `observed` table
  rendered on every run, so a clean session is still a useful session
  recap rather than just "none found", plus a merged chronological
  timeline behind a `--timeline` flag. Every collector already timestamps
  its data, so this is a rendering layer over what's already recorded and
  will work retroactively on sessions you've already captured.
- OpenCode, Cursor, and other agent claim-log parsers (the `claim.Source`
  interface already anticipates this)
- Network egress allowlist configuration (`--allow-host` or a config file)
- `/proc/net` inode→fd mapping for more precise Linux network attribution
- eBPF-based collection for lower-latency, harder-to-miss process and
  network observation
- HTML report output
- Windows process/network collection

## Contributing

Issues and PRs welcome. The hard constraints that shape every design
decision here: zero third-party dependencies (Go standard library only —
if you think a dependency is needed, open an issue and make the case first
rather than sending a PR that adds one), no pty/stream interception under
any circumstance, and no feature that blocks, kills, sandboxes, or modifies
the wrapped process. If a change doesn't serve "observed vs claimed," it's
probably out of scope.

```
go vet ./...
go test ./...
```

Both must pass clean before a PR is considered.

## License

MIT — see [LICENSE](LICENSE).
