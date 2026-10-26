# scan_sweep.py command reference

All commands except `collect` read the newest snapshot in `~/.cache/tenable-scan-sweep/`
(or `$SCAN_SWEEP_HOME`), or the file passed with `--snapshot`. Output is markdown by
default; `--format json` is the full structured result and `--format csv` is a flat
table, where offered.

## collect

Reads every scan's configuration and writes the snapshot.

| Option | Default | Meaning |
|---|---|---|
| `--platform` | `vm` | `vm` for Tenable Vulnerability Management, `sc` for Tenable Security Center |
| `--url` | vm: `$TIO_URL`, else `https://cloud.tenable.com`; sc: `$TSC_URL` (required) | Platform URL |
| `--env-prefix` | `TIO` for vm, `TSC` for sc | Reads `<PREFIX>_ACCESS_KEY` / `<PREFIX>_SECRET_KEY` (and `<PREFIX>_URL`), for keeping several containers' keys side by side. A non-default prefix is added to the snapshot name |
| `--workers` | `4` | VM only. Concurrent requests. pyTenable retries 429 responses with backoff, so raising this rarely helps |
| `--ca-bundle` | none | SC only. CA bundle used to verify the Security Center certificate |
| `--insecure` | off | SC only. Skip TLS certificate verification. Not recommended |
| `--snapshot` | `$SCAN_SWEEP_HOME` or `~/.cache/tenable-scan-sweep/`, file `<host>.json` (`<host>-<prefix>.json` with a non-default `--env-prefix`) | Output file |
| `--assets` | off | VM: also build an asset index (one asset export plus the agent list), so `find` resolves tag-targeted and agent scans for a specific IP or hostname. SC: also read the current members of the rule-based asset lists that scans use |
| `--include-credential-summaries` | off | Also keep summaries of scan-specific credentials (may include usernames) |

### Vulnerability Management

API calls, all `GET`:

- `/scans` with `limit`/`offset`. If the response includes a `pagination` object, the
  script keeps paging until it has `pagination.total` scans. Otherwise the parameters are
  ignored and the single response holds every scan.
- `/editor/scan/{id}`, once per scan. This one response holds the targets and the name
  lists for tags, agent groups, target groups, scanners, networks and policies.
- `/editor/policy/{id}`, once per distinct user-defined policy, for its credentials.
- `/scans?folder_id=<trash folder>`, to skip scans in the trash.
- `/exclusions`, paged the same way as `/scans`.
- With `--assets`: `POST /assets/export` (v1, `chunk_size` 4000), then its status and chunks,
  and `/scanners/null/agents`, paged. If collection stops before the job finishes, the
  tool cancels it (`POST /assets/export/{uuid}/cancel`). These are the tool's only non-GET
  requests. It never adopts another integration's running export (`adopt_existing=False`).
  The job changes no configuration. If the agent list can't be read (it needs Scan
  Manager), the index keeps the assets and records a `collect-error`. The index keeps each asset's IPs, names
  (FQDNs, hostnames, NetBIOS names), tags and agent ID, and each agent's IP, name and group
  names. Asset export v1 is used because v2 omits those identifier fields.

### Security Center

API calls, all `GET`, under `/rest`:

- `/system`: pyTenable's version check (SC 5.13 or later is required for API keys).
- `/asset?fields=id,name,type,typeFields`. A static or DNS-name list returned without
  `typeFields` is read again with `/asset/{id}`.
- `/policy?fields=id,name,policyTemplate`: maps each policy to its template, for the
  `uncredentialed` check.
- `/scan?fields=…`: one call returns every usable and manageable scan with its targets,
  asset lists, repository, scan zone, policy, credentials and schedule.
- `/freeze`, falling back to `/blackout` (the older name for freeze windows) when `/freeze` returns an error.
- With `--assets`: `/asset/{id}?fields=id,name,type,viewableIPs` for each rule-based list a
  scan uses, one list at a time (the API warns that requesting `viewableIPs` for every list
  at once can be slow). Members are the union across repositories. A list whose response has
  no `viewableIPs` stays unresolved. `status` reports `rule_lists_used` and
  `rule_lists_resolved`.

How SC concepts map onto the snapshot:

| SC | Snapshot / output |
|---|---|
| Scan `ipList` | Text targets |
| Static, DNS-name and watchlist asset lists | Target groups, expanded to their members |
| Dynamic, combination, LDAP query and other rule-based asset lists | Target groups that can't be expanded. `find` reports them as unresolved; `--asset-list` supplies membership |
| Scan zone | `scanner` (zone `0` is "All zones (automatic)") |
| Repository | `network`; `overlaps` compares scans only within one repository |
| Freeze or blackout window | Exclusion. A window can cover all IPs |
| Policy template (or "Single plugin scan") | `template` |
| Schedule types `ical`, `dependent`, `rollover`, `template`/`never`/`now` | `weekly (MO)`…, `after '<scan>'`, `rollover`, `on demand` |

A scan whose configuration can't be read (for example, permissions) is listed under
`errors` and reported by `audit`.

## find TARGET… [--asset-tag CATEGORY:VALUE]… [--asset-list NAME]…

Targets may be any VM target format (IPv4/IPv6 address, `ip:port`, CIDR, netmask, `a-b`
range, octet range, hostname, `Label[ip]`) or a selector:

| Selector | Matches |
|---|---|
| `tag:Category:Value` | Scans targeting that tag (exact). `tag:Austin` matches any tag containing "Austin" |
| `agent-group:NAME` | Agent scans using a group whose name contains NAME |
| `target-group:NAME` or `asset-list:NAME` | Scans using a VM target group, or an SC asset list of any type, whose name contains NAME |
| `scanner:NAME` or `zone:NAME` | Scans assigned to that scanner, scanner group or SC scan zone |
| `credential:TEXT` | Scans whose credentials' category, type or managed name contains TEXT (`SSH`, `Windows`, `Database`) |
| `policy:NAME`, `template:NAME`, `network:NAME` (or `repository:NAME` for SC), `owner:TEXT` | As named |

JSON fields per query:

- `matches[]`: `id, name, kind, enabled, schedule, scanner, network, template, matched_by[]`.
  A reason ending "(approximate …)" came from a bounded octet range.
- `excluded_by[]`: `name, schedule_enabled, network`. Disabled SC freeze windows are ignored.
- `possibly_excluded_by[]` (SC): enabled freeze windows that use asset lists the snapshot
  couldn't expand, with `unresolved_lists[]`.
- `exclusions_collected`: `false` when exclusions or freeze windows couldn't be read, so an
  empty `excluded_by` doesn't mean "not excluded".
- `unchecked_scans`: counts of scans that couldn't be checked offline, by cause.
- `unresolved_tag_scans`, `unresolved_tags[]`: tag-targeted scans that couldn't be checked.
- `asset_index` (when the snapshot has one): `assets_matched`, `tags[]`, `agents_matched`,
  `agent_groups[]` for the queried address. Matches it adds say "(from asset index)".
- `unresolved_list_scans`, `unresolved_lists[]` (SC): scans using rule-based asset lists that
  couldn't be checked. Pass `--asset-list NAME` for each list the asset belongs to.
- `agent_scans_not_checked`.

## overlaps [--include-disabled] [--min-shared N] [--limit N]

Pairs of network scans in the same VM network (or SC repository) whose text targets and target groups share
addresses. The fields are `network`, `shared_addresses`, `pct_of_a`, `pct_of_b`,
`identical`, `same_template`, `approximate` and `schedules`. Identical pairs sort first. Tag and agent targets aren't compared.

## audit

| Check | Severity | Meaning |
|---|---|---|
| `no-targets` | warn (info if the scan has no enabled schedule) | Network scan with no targets of any kind |
| `no-agent-groups` | warn | Agent scan with no agent groups |
| `unparsed-targets` | warn | Target text that isn't a valid VM target (pasted rich text, URLs, partial IPs) |
| `uncredentialed` | warn | Template that normally uses credentials (Basic/Advanced Network, SC Advanced Scan, Custom, Credentialed Patch Audit, Internal PCI, Policy Compliance, SCAP/OVAL, Malware) with no credentials in the scan or its policy |
| `duplicate-targets` | warn | Two scheduled scans with identical target sets |
| `collect-error` | warn | Something couldn't be read: a scan, policy, asset list, the exclusions or freeze windows, the agent list, or the asset index |
| `dns-dependent-subnet` | info | `hostname/mask` targets, whose scope changes with DNS |
| `large-target` | info | More than 65,536 addresses |
| `approximate-targets` | info | Very large octet ranges were bounded rather than expanded |
| `target-groups` | info | Uses target groups; VM recommends tags |
| `on-demand` | info | No enabled schedule and no triggers |
| `unused-agent-group`, `unused-target-group`, `unused-scanner` | info | VM: listed in the scan editor but referenced by no scan (scanner groups are skipped) |
| `asset-lists-not-scan-targets` | info | SC: how many asset lists no scan uses. SC asset lists also drive analysis, dashboards and access, so it's a count, not a finding per list |
| `tags-not-scan-targets` | info | Count of tags offered as targets that no scan uses |

## credentials

The fields are `by_type` (credential category/type → scans), `managed` (managed
credential name → scans) and `uncredentialed_scans[]`. `--format csv` outputs only
`uncredentialed_scans`.

## show SCAN

One scan's normalized configuration, with names resolved and the target address count.
SCAN is an ID or part of a name (a number that isn't an ID is tried as a name); up to 10
matches are shown.

## list

One row per scan: `id, name, kind, template, enabled, schedule, scanner, network,
text_targets, target_groups, tags, agent_groups, addresses, credentials, owner`.

## status

The snapshot's path, container, collection time, age and stale flag (over 24 hours),
plus counts by scan kind and inventory sizes, and the number of collection errors (see
`audit` for details).
