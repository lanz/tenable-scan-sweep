# Tenable Scan Sweep

[![Listed on CyberAgents Exchange](https://img.shields.io/badge/CyberAgents%20Exchange-Listed-E7FF00?style=flat-square&labelColor=1E2426)](https://exchange.tenable.com/skills/tenable-scan-sweep/)

A Claude Code skill and command-line tool. It answers "which scans target X?" and other
scan-configuration questions across every scan in Tenable Vulnerability Management (VM) or
Tenable Security Center (SC).

The VM UI can't search scans by target. The API needs one call per scan to read a target
list. An assistant or MCP server making those calls spends tokens and tool calls on every
scan, and runs out of either long before a container with hundreds of scans is done. This
tool makes the calls itself once, read-only, into a local snapshot, and then answers
questions from the snapshot instantly:

- **Which scans target** an IP, CIDR, range, hostname, tag, agent group, target group or
  SC asset list, scanner or scan zone, repository, credential type, policy, template or
  owner? Is the address under a VM exclusion or an SC freeze window?
- **Which scans overlap** or scan exactly the same addresses?
- **Scan hygiene:** scans with no targets, credentialed templates without credentials,
  unparsable targets, on-demand-only scans, deprecated target groups, and unused agent
  groups, target groups and scanners.
- **Credential usage:** which scans use which credential types and managed credentials.

## Prerequisites

- Python 3.11 or later, and [uv](https://docs.astral.sh/uv/) (recommended) or pip.
- A Tenable VM API key pair. Reading scan configurations requires the Standard role (or
  the `VM.VM_SCAN.VM_SCAN.EDIT` privilege), and reading exclusions requires Scan Manager
  (or `VM.VM_SCAN.VM_SCAN_EXCLUSION.READ`). Results only cover scans the user can see, so use
  an administrator's keys for a complete sweep. Generate keys under
  **Settings > My Account > API Keys**.
- For `collect --assets` on VM: the asset export needs the Basic role (or
  `VM.VM_EXPLORE.VM_EXPLORE.EXPORT`) and Can View on the assets, and the agent list needs
  Scan Manager (or `VM.VM_SENSOR.VM_AGENT.READ`). Without the agent list, agent scans stay
  unresolved.
- Or, for Security Center: an SC API key pair (SC 5.13 or later) for an organization user
  who can use or manage the scans you want covered, and the SC URL. Administrator accounts
  can't see scans.
- For the skill: [Claude Code](https://docs.claude.com/en/docs/claude-code).

## Installation

### As a Claude Code skill

Clone into your personal skills directory, which makes it available in every project:

```bash
git clone https://github.com/lanz/tenable-scan-sweep ~/.claude/skills/tenable-scan-sweep
```

Or clone into a single project's `.claude/skills/tenable-scan-sweep`. Claude Code loads the
skill from `SKILL.md` and uses it when you ask about scan targets or scan configuration. You
can also invoke it directly with `/tenable-scan-sweep`.

### Standalone

```bash
git clone https://github.com/lanz/tenable-scan-sweep
cd tenable-scan-sweep
uv run scripts/scan_sweep.py --help        # uv installs pyTenable from the script's metadata
# or: pip install pytenable && python scripts/scan_sweep.py --help
```

## How to run it

Set your keys in the environment. Never pass them as arguments.

```bash
export TIO_ACCESS_KEY=...   # PowerShell: $env:TIO_ACCESS_KEY = '...'
export TIO_SECRET_KEY=...
export TIO_URL=https://cloud.tenable.com   # optional; this is the default

# Security Center instead:
export TSC_ACCESS_KEY=...
export TSC_SECRET_KEY=...
export TSC_URL=https://sc.example.com      # required; SC has no default address
```

With the skill installed, ask Claude Code things like:

> Which scans target 10.20.4.17? It's tagged Location:Austin.
> Do any of our scans scan the same networks?
> Give me a health check of our scan configurations.
> Which scans use the "Linux service account" credential?

Or run the commands yourself:

```bash
uv run scripts/scan_sweep.py collect                      # VM: one request per scan
uv run scripts/scan_sweep.py collect --platform sc        # SC: a handful of requests
uv run scripts/scan_sweep.py collect --platform sc --ca-bundle corp-ca.pem   # SC behind a private CA
uv run scripts/scan_sweep.py collect --assets             # VM: also index assets and agents
uv run scripts/scan_sweep.py find 10.20.4.17 web01.example.com
uv run scripts/scan_sweep.py find 10.20.4.17 --asset-tag Location:Austin   # without an index
uv run scripts/scan_sweep.py find agent-group:"Web servers"
uv run scripts/scan_sweep.py overlaps
uv run scripts/scan_sweep.py audit
uv run scripts/scan_sweep.py credentials
uv run scripts/scan_sweep.py show "Weekly DMZ"
uv run scripts/scan_sweep.py list --format csv > scans.csv
```

[`references/commands.md`](references/commands.md) documents every command, option and
output field.

## Output

The output is a markdown report by default, or `--format json` / `--format csv`. This
example uses synthetic data:

```text
$ scan_sweep.py find 192.0.2.10
_Snapshot of 8 Vulnerability Management scans from cloud.tenable.com, collected 2026-10-22T22:47:45+00:00._

## 192.0.2.10

2 scan(s) target this.

| id | name | kind | enabled | schedule | scanner | network | template | matched_by |
|---|---|---|---|---|---|---|---|---|
| 1 | Weekly DMZ | network | True | weekly (MO) | Austin scanner | Default | Basic Network Scan | target 192.0.2.0/24 |
| 2 | DMZ copy | network | True | weekly (MO) | Austin scanner | Default | Basic Network Scan | target 192.0.2.0-192.0.2.255 |

**Excluded by:** 'Maintenance window'

Not checked offline, and may also target this: 1 scan(s) with hostname targets (IP query
not resolved to names).

1 more scan(s) target by tag and may include this asset: Location:Austin. Rerun with
`--asset-tag Category:Value` for each tag the asset has.

1 agent scan(s) target agent groups, not addresses; check the agent's groups separately.
```

```text
$ scan_sweep.py audit
**Summary:** duplicate-targets: 1, no-targets: 1, on-demand: 1, target-groups: 1, uncredentialed: 6, ...

| severity | check | scan | scan_id | detail |
|---|---|---|---|---|
| warn | duplicate-targets |  |  | 'Weekly DMZ' and 'DMZ copy' scan identical targets (256 addresses, weekly (MO) / weekly (MO)). |
| warn | no-targets | Empty | 7 | No text targets, target groups, tags or target file. |
| warn | unparsed-targets | Weekly DMZ | 1 | Targets not in a recognized format: bad target!! |
| info | unused-agent-group |  |  | agent group 'Databases' isn't referenced by any scan. |
```

## Data handling and network access

- **Read-only.** Every request is a `GET`, except for `collect --assets` on VM, described
  below.
  - VM: `/scans` (including the trash folder, to skip it), `/editor/scan/{id}`,
    `/editor/policy/{id}` and `/exclusions`.
  - VM with `--assets`: `POST /assets/export` starts one asset export job, then the tool
    reads its status and chunks, and `/scanners/null/agents`. If collection stops before
    the job finishes, it cancels the job (`POST /assets/export/{uuid}/cancel`). It never
    adopts another integration's running export. The job changes no configuration, but
    it counts toward the container's 10 concurrent exports.
  - SC: `/rest/system`, `/rest/scan`, `/rest/asset` (and `/rest/asset/{id}` for lists the
    list response doesn't fully describe, and with `--assets` for rule-based members),
    `/rest/policy` and `/rest/freeze` (or `/rest/blackout`).
  - It makes no requests to any other host, sends no telemetry, and never creates, changes
    or launches scans.
- **TLS.** SC certificates are verified by default. Pass `--ca-bundle` for a private CA;
  `--insecure` turns verification off, which isn't recommended.
- **Credentials** are read from environment variables, passed to pyTenable, and never
  logged or stored. The User-Agent identifies the tool as `tenable-scan-sweep`.
- **The snapshot** is written to `~/.cache/tenable-scan-sweep/<host>.json`, or
  `<host>-<prefix>.json` with a non-default `--env-prefix` (override with `--snapshot` or
  `SCAN_SWEEP_HOME`). The tool makes it owner-only on systems that support
  it. It contains scan names, targets, owners and schedules, which is internal network
  information, so treat it accordingly and don't commit it. Credential secrets are never
  collected. Managed credentials are recorded by name, and summaries of scan-specific
  credentials (which can include usernames) are left out unless you pass
  `--include-credential-summaries`.
- **With the skill**, Claude reads the command output, so scan names and targets that
  match your question enter the conversation and go to the model provider like anything
  else you share. Credentials never do.

## Known limitations

- **Vulnerability Management and Security Center only.** Standalone Nessus scans aren't
  covered, and Web App Scanning scans don't appear in the VM scan list.
- **Rule-based SC asset lists** (dynamic, combination, LDAP query and similar) are expanded
  only with `collect --assets`. Without it, pass the lists the asset belongs to with
  `--asset-list`. Static, DNS-name and watchlist lists are always expanded.
- **Tag targets need the asset index.** Without `collect --assets`, the tool knows which tags
  a scan targets but not which assets carry them; pass the asset's tags with `--asset-tag`.
  With the index, `find` looks them up for any address VM knows about. Tag rules aren't
  evaluated, so an address that VM has never seen can't be matched to a tag.
- **Agent scans** target agent groups, not addresses. With the asset index, `find` matches an
  agent to its groups automatically; without it, look them up by group name.
- **On Security Center, `--assets` reads rule-based asset list members** at collection time,
  so matches reflect the lists as they were then. A list type that doesn't report members
  stays unresolved.
- **SC administrator accounts can't see scans.** Security Center keeps scans out of the
  administrator role, so use keys for an organization user.
- **No DNS resolution.** Hostname targets match by name, and `hostname/24`-style targets
  are flagged rather than expanded. An IP query doesn't match a scan that lists the same
  host by name.
- `find` reports how many scans it couldn't check offline: uploaded target files,
  `hostname/mask` targets, hostname targets when you search for an IP, and unparsed targets.
- Scans in the trash are skipped. `overlaps` compares only scans in the same VM network
  or SC repository.
- **Exclusion schedules** aren't evaluated. The tool reports that an exclusion covers a
  target, and whether it's scheduled.
- **Uploaded target files** (`file_targets`) can't be read through the API. Scans using
  them are counted as having targets but aren't searched.
- The `uncredentialed` check is a heuristic based on the scan template. It also considers
  credentials stored in the scan's policy.
- Very large octet ranges (for example `10.0-255.0-255.1-254`) are approximated by their
  bounding range, and flagged as approximate.
- The snapshot is a point in time. `status` reports its age, and anything over 24 hours is
  flagged as stale.
- The target parser follows the documented VM target formats. Please open an issue if a
  valid target is reported as unparsed.

## Development

```bash
pip install pytenable pytest responses ruff
pytest
ruff check scripts tests
```

The tests use synthetic data and mocked HTTP. They don't contact a Tenable container.
The tool has also been run against live Tenable VM containers, including one with a
paginated scan list, and live Security Centers. CI
runs them on Python 3.11 to 3.13.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 [Lance Duvall](https://github.com/lanz).

## Disclaimer

This is an independent open source community project. It is not an official Tenable
product and is not affiliated with, sponsored by, endorsed by, or supported by
Tenable, Inc.

Tenable, Nessus and other Tenable product names are trademarks or registered trademarks
of Tenable, Inc. Other names may be trademarks of their respective owners.
