# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Lance Duvall
# Project: <https://github.com/lanz/tenable-scan-sweep>
# /// script
# requires-python = ">=3.11"
# dependencies = ["pytenable>=26.10.1"]
# ///
"""
Tenable Scan Sweep: answer "which scans target X?" across every scan in Tenable
Vulnerability Management or Tenable Security Center, without spending model tokens on
hundreds of API calls.

``collect`` reads every scan configuration and writes a local snapshot. On VM that's one
``GET /editor/scan/{id}`` call per scan; on Security Center (``--platform sc``) it's a
handful of list calls. Every other command works offline from that snapshot.

    scan_sweep.py collect
    scan_sweep.py find 10.0.4.17 web01.example.com tag:Location:Austin
    scan_sweep.py overlaps
    scan_sweep.py audit
    scan_sweep.py credentials
    scan_sweep.py show "Weekly DMZ"
    scan_sweep.py list --format csv

Credentials come from environment variables only: ``TIO_ACCESS_KEY`` and
``TIO_SECRET_KEY`` (optional ``TIO_URL``) for VM, or ``TSC_ACCESS_KEY``,
``TSC_SECRET_KEY`` and ``TSC_URL`` for Security Center. Every request is a ``GET``,
except that ``collect --assets`` on VM starts one asset export job (and cancels it if
collection stops early).
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import ipaddress
import itertools
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

VERSION = '1.0.0'
DEFAULT_URL = 'https://cloud.tenable.com'
PAGE_SIZE = 200
STALE_HOURS = 24
# Octet-range targets such as 10.0-255.0-255.1-254 can expand to millions of blocks.
# Past this many intervals, use one bounding interval and mark the target approximate.
MAX_OCTET_INTERVALS = 4096
LARGE_TARGET_ADDRESSES = 65536

# Templates where missing credentials usually mean a coverage gap. Discovery, PCI
# external, agent and web app templates don't use host credentials.
CREDENTIALED_TEMPLATES = {
    'advanced network scan',
    'advanced scan',
    'basic network scan',
    'custom scan',
    'credentialed patch audit',
    'internal pci network scan',
    'policy compliance auditing',
    'scap and oval auditing',
    'malware scan',
}

HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*\.?$')
BRACKET_RE = re.compile(r'^(?P<label>.*)\[(?P<inner>[^\]]+)\]$')
IPV4_PORT_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$')
OCTET_RE = re.compile(r'^(\d{1,3}(?:-\d{1,3})?)\.(\d{1,3}(?:-\d{1,3})?)\.(\d{1,3}(?:-\d{1,3})?)\.(\d{1,3}(?:-\d{1,3})?)$')
HOST_SUBNET_RE = re.compile(r'^(?P<host>[A-Za-z0-9_.-]+)/(?P<mask>\d{1,2}|\d{1,3}(?:\.\d{1,3}){3})$')
UUID_RE = re.compile(r'^[0-9a-fA-F-]{32,36}$')


# --------------------------------------------------------------------------------------
# Target parsing
# --------------------------------------------------------------------------------------


def split_targets(text: str | None) -> list[str]:
    """Split a scan's target text on commas and newlines, the separators Tenable accepts."""
    if not text:
        return []
    return [t.strip() for t in re.split(r'[,\n\r]+', text) if t.strip()]


def _interval(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return (net.version, int(net.network_address), int(net.broadcast_address))


def _octet_values(part: str) -> tuple[int, int] | None:
    lo, _, hi = part.partition('-')
    lo_i, hi_i = int(lo), int(hi or lo)
    if not (0 <= lo_i <= hi_i <= 255):
        return None
    return lo_i, hi_i


def parse_target(raw: str) -> dict[str, Any]:
    """
    Classify one target in any of the formats VM accepts and return its address
    intervals. ``kind`` is one of ip, network, range, octets, hostname, hostname-subnet,
    link6 or unknown. ``intervals`` holds (ip version, first int, last int) tuples.
    """
    token = raw.strip()
    result: dict[str, Any] = {'raw': raw, 'kind': 'unknown', 'intervals': [], 'hostname': None}
    if token.startswith("'") and token.endswith("'") and len(token) > 2:
        # Quoting forces Tenable to treat the target as a hostname.
        result.update(kind='hostname', hostname=token[1:-1].lower().rstrip('.'))
        return result
    bracket = BRACKET_RE.match(token)
    if bracket:
        inner = parse_target(bracket['inner'])
        inner.update(raw=raw, label=bracket['label'].strip())
        return inner
    if token.lower().startswith('link6'):
        result['kind'] = 'link6'
        return result
    port = IPV4_PORT_RE.match(token)
    if port:
        token = port.group(1)
    try:
        addr = ipaddress.ip_address(token)
        net = ipaddress.ip_network(addr.compressed.split('%')[0])
        result.update(kind='ip', intervals=[_interval(net)])
        return result
    except ValueError:
        pass
    if '/' in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            result.update(kind='network', intervals=[_interval(net)])
            return result
        except ValueError:
            pass
    if '-' in token:
        start, _, end = token.partition('-')
        try:
            a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
            if a.version == b.version and int(a) <= int(b):
                result.update(kind='range', intervals=[(a.version, int(a), int(b))])
                return result
        except ValueError:
            pass
        octets = OCTET_RE.match(token)
        if octets:
            parts = [_octet_values(p) for p in octets.groups()]
            if all(parts):
                result.update(kind='octets', **_octet_intervals(parts))
                return result
    # Anything made only of digits, dots, dashes and slashes is a malformed address or
    # range (10.0.0/24, 10.0.0.5-3), not a hostname. Report it so `audit` can flag it.
    if not re.search(r'[A-Za-z_]', token):
        return result
    host_subnet = HOST_SUBNET_RE.match(token)
    if host_subnet and not _is_ip(host_subnet['host']):
        result.update(kind='hostname-subnet', hostname=host_subnet['host'].lower().rstrip('.'))
        return result
    if HOSTNAME_RE.match(token):
        result.update(kind='hostname', hostname=token.lower().rstrip('.'))
    return result


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _octet_intervals(parts: list[tuple[int, int]]) -> dict[str, Any]:
    (a1, a2), (b1, b2), (c1, c2), (d1, d2) = parts
    combos = (a2 - a1 + 1) * (b2 - b1 + 1) * (c2 - c1 + 1)
    if combos > MAX_OCTET_INTERVALS:
        start = (a1 << 24) | (b1 << 16) | (c1 << 8) | d1
        end = (a2 << 24) | (b2 << 16) | (c2 << 8) | d2
        return {'intervals': [(4, start, end)], 'approximate': True}
    intervals = []
    for a, b, c in itertools.product(range(a1, a2 + 1), range(b1, b2 + 1), range(c1, c2 + 1)):
        base = (a << 24) | (b << 16) | (c << 8)
        intervals.append((4, base | d1, base | d2))
    return {'intervals': intervals}


def merge_intervals(intervals: Iterable[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    merged: list[list[int]] = []
    for version, start, end in sorted(intervals):
        if merged and merged[-1][0] == version and start <= merged[-1][2] + 1:
            merged[-1][2] = max(merged[-1][2], end)
        else:
            merged.append([version, start, end])
    return [tuple(m) for m in merged]  # type: ignore[misc]


def overlap_size(a: list[tuple[int, int, int]], b: list[tuple[int, int, int]]) -> int:
    """Number of addresses shared by two merged, sorted interval lists."""
    i = j = total = 0
    while i < len(a) and j < len(b):
        va, sa, ea = a[i]
        vb, sb, eb = b[j]
        if (va, ea) < (vb, sb):
            i += 1
            continue
        if (vb, eb) < (va, sa):
            j += 1
            continue
        if va == vb:
            lo, hi = max(sa, sb), min(ea, eb)
            if lo <= hi:
                total += hi - lo + 1
        if (va, ea) <= (vb, eb):
            i += 1
        else:
            j += 1
    return total


def address_count(intervals: list[tuple[int, int, int]]) -> int:
    return sum(end - start + 1 for _, start, end in intervals)


def describe_interval(interval: tuple[int, int, int]) -> str:
    version, start, end = interval
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    if start == end:
        return str(cls(start))
    return f'{cls(start)}-{cls(end)}'


# --------------------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------------------


def connect(env_prefix: str, url: str | None):
    from tenable.io import TenableIO

    access = os.environ.get(f'{env_prefix}_ACCESS_KEY')
    secret = os.environ.get(f'{env_prefix}_SECRET_KEY')
    if not access or not secret:
        sys.exit(
            f'error: set {env_prefix}_ACCESS_KEY and {env_prefix}_SECRET_KEY in the environment '
            '(API keys for a user who can view the scans you want to sweep).'
        )
    url = url or os.environ.get(f'{env_prefix}_URL') or DEFAULT_URL
    return TenableIO(
        url=url.rstrip('/'),
        access_key=access,
        secret_key=secret,
        vendor='Tenable Community',
        product='tenable-scan-sweep',
        build=VERSION,
    )


def list_all_scans(tio) -> tuple[list[dict], dict]:
    """
    List every scan. Send limit/offset on every request. If the response carries a
    ``pagination`` object, keep paging until ``pagination.total`` scans are read, because
    a paginated response holds only one page. An unpaginated response ignores the
    parameters and returns every scan.
    """
    scans, first = _paged(tio, 'scans', 'scans')
    folders = first.get('folders') or []
    meta: dict[str, Any] = {'paginated': bool(first.get('pagination'))}
    if first.get('pagination'):
        meta['reported_total'] = int(first['pagination'].get('total', len(scans)))
    unique = {s['id']: s for s in scans}
    # Scans in the Trash folder are still listed. Scan records don't say which folder
    # they're in, so list the trash folder separately and drop those scans.
    trash = [f['id'] for f in folders if f.get('type') == 'trash']
    trashed: set = set()
    for folder_id in trash:
        trashed_scans, _ = _paged(tio, 'scans', 'scans', {'folder_id': folder_id})
        trashed |= {s['id'] for s in trashed_scans}
    meta['listed'] = len(unique)
    meta['trashed_skipped'] = len(trashed & set(unique))
    meta['folders'] = {f['id']: f.get('name') for f in folders if 'id' in f}
    return [s for sid, s in unique.items() if sid not in trashed], meta


def _paged(tio, path: str, key: str, params: dict | None = None) -> tuple[list[dict], dict]:
    """Read every page of a list endpoint that may or may not return a pagination object."""
    params = dict(params or {})
    first = tio.get(path, params={**params, 'limit': PAGE_SIZE, 'offset': 0}).json()
    items = list(first.get(key) or [])
    pagination = first.get('pagination')
    if pagination:
        total = int(pagination.get('total', len(items)))
        while len(items) < total:
            page = tio.get(path, params={**params, 'limit': PAGE_SIZE, 'offset': len(items)}).json()
            batch = page.get(key) or []
            if not batch:
                break
            items.extend(batch)
    return items, first


def _walk_inputs(node: Any, found: dict[str, dict]) -> None:
    if isinstance(node, dict):
        if isinstance(node.get('id'), str) and ('default' in node or 'options' in node):
            found.setdefault(node['id'], node)
        for key, value in node.items():
            if key != 'modes':
                _walk_inputs(value, found)
    elif isinstance(node, list):
        for item in node:
            _walk_inputs(item, found)


def _option_label(field: dict | None) -> dict | None:
    if not field or field.get('default') in (None, ''):
        return None
    value = field['default']
    for opt in field.get('options') or []:
        if isinstance(opt, dict) and str(opt.get('value', opt.get('id'))) == str(value):
            return {'value': value, 'label': opt.get('name')}
    return {'value': value, 'label': None}


def normalize_scan(summary: dict, editor: dict, inventory: dict, include_cred_summaries: bool) -> dict:
    fields: dict[str, dict] = {}
    _walk_inputs(editor.get('settings', {}), fields)

    def default(name: str, fallback: Any = None) -> Any:
        field = fields.get(name)
        return field.get('default', fallback) if field else fallback

    def options(name: str) -> list:
        field = fields.get(name)
        return (field.get('options') or []) if field else []

    # Inventories come from the editor's option lists, so no extra API calls are needed.
    for opt in options('agent_group_id'):
        inventory['agent_groups'][str(opt.get('id'))] = opt.get('name')
    for opt in options('tag_targets'):
        inventory['tags'][opt.get('uuid')] = {'category': opt.get('category_name'), 'value': opt.get('value')}
    for opt in options('asset_lists'):
        inventory['target_groups'][str(opt.get('id'))] = {
            'name': opt.get('name'),
            'members': split_targets(opt.get('members')),
            'type': opt.get('type'),
        }
    for opt in options('scanner_id'):
        inventory['scanners'][str(opt.get('id'))] = {
            'name': opt.get('name'),
            'type': opt.get('type'),
            'status': opt.get('status'),
        }
    for opt in options('target_network_uuid'):
        inventory['networks'][str(opt.get('value'))] = opt.get('name')
    for opt in options('policy_id'):
        inventory['policies'][str(opt.get('id'))] = opt.get('name')

    basic: dict[str, Any] = {}
    for group in editor.get('settings', {}).get('basic', {}).get('groups', []):
        for key, value in group.items():
            if key not in ('name', 'title', 'inputs', 'sections'):
                basic[key] = value

    scanner_id = default('scanner_id')
    scanner = inventory['scanners'].get(str(scanner_id), {}) if scanner_id else {}
    network_uuid = default('target_network_uuid')
    policy_id = default('policy_id')

    credentials = parse_credentials(editor, include_cred_summaries, source='scan')

    return {
        'id': summary.get('id'),
        'schedule_uuid': summary.get('schedule_uuid'),
        'name': summary.get('name') or editor.get('name'),
        'type': summary.get('type'),
        'template': editor.get('title'),
        'owner': summary.get('owner'),
        'folder_id': summary.get('folder_id'),
        'status': summary.get('status'),
        'enabled': summary.get('enabled'),
        'has_triggers': summary.get('has_triggers'),
        'created': summary.get('creation_date'),
        'modified': summary.get('last_modification_date'),
        'policy': {'id': policy_id, 'name': inventory['policies'].get(str(policy_id))} if policy_id else None,
        'scanner': {'id': scanner_id, 'name': scanner.get('name'), 'type': scanner.get('type')} if scanner_id else None,
        'network': {'uuid': network_uuid, 'name': inventory['networks'].get(str(network_uuid))} if network_uuid else None,
        'targets': {
            'text': split_targets(default('text_targets')),
            'file_targets': bool(default('file_targets')),
            'target_groups': [str(x) for x in default('asset_lists') or []],
            'tags': [str(x) for x in default('tag_targets') or []],
            'tag_mode': _option_label(fields.get('use_tag_rules_as_targets')) if default('tag_targets') else None,
            'tag_ip_selection': _option_label(fields.get('tag_targets_ip_selection')) if default('tag_targets') else None,
            'agent_groups': [str(x) for x in default('agent_group_id') or []],
        },
        'schedule': {
            'enabled': basic.get('enabled'),
            'rrules': basic.get('rrules'),
            'starttime': basic.get('starttime'),
            'timezone': basic.get('timezone'),
            'agent_scan_launch_type': basic.get('agent_scan_launch_type'),
            'triggers': len(basic.get('triggers') or []),
        },
        'credentials': credentials,
        'compliance_audits': len((editor.get('compliance') or {}).get('data', [])),
    }


def parse_credentials(editor: dict, include_summaries: bool, source: str) -> list[dict]:
    """
    Credential instances from an editor document. Only the category, type and managed
    flag are kept; secrets never are. Summaries are kept for managed credentials (their
    name) and, with ``include_summaries``, for ad hoc ones, which can contain usernames.
    """
    credentials = []
    for ctype in (editor.get('credentials') or {}).get('data', []):
        for item in ctype.get('types', []):
            for inst in item.get('instances', []):
                managed = not inst.get('ad_hoc', True)
                cred = {'category': ctype.get('name'), 'type': item.get('name'), 'managed': managed, 'source': source}
                if managed and UUID_RE.match(str(inst.get('id', ''))):
                    cred['id'] = inst['id']
                if include_summaries or managed:
                    cred['summary'] = inst.get('summary')
                credentials.append(cred)
    return credentials


def _list_exclusions(tio) -> list[dict]:
    items, _ = _paged(tio, 'exclusions', 'exclusions')
    out = []
    for ex in items:
        schedule = ex.get('schedule') or {}
        out.append(
            {
                'id': ex.get('id'),
                'name': ex.get('name'),
                'members': split_targets(ex.get('members')),
                'schedule_enabled': schedule.get('enabled'),
                'rrules': schedule.get('rrules'),
                'network_id': ex.get('network_id'),
            }
        )
    return out


# --------------------------------------------------------------------------------------
# Security Center collection
# --------------------------------------------------------------------------------------

SC_SCAN_FIELDS = (
    'id,uuid,name,description,status,type,ipList,assets,repository,zone,policy,plugin,'
    'credentials,schedule,owner,createdTime,modifiedTime'
)
# Asset list types whose members are literal addresses or hostnames. Every other type
# (dynamic, combination, ldapquery, templates…) is defined by rules, so its members
# can't be known offline.
SC_LITERAL_LIST_TYPES = {'static', 'dnsname', 'dnsnameupload', 'upload', 'watchlist'}
# Schedule types that launch a scan without someone starting it. A 'template' (on-demand)
# schedule reports enabled=true too, so the flag alone doesn't mean scheduled.
SC_SCHEDULED_TYPES = {'ical', 'dependent', 'rollover'}
SC_WINDOW_FIELDS = 'id,name,ipList,assets,repository,enabled,repeatRule,start,end,allIPs'


def connect_sc(env_prefix: str, url: str | None, verify: bool | str):
    from tenable.sc import TenableSC

    access = os.environ.get(f'{env_prefix}_ACCESS_KEY')
    secret = os.environ.get(f'{env_prefix}_SECRET_KEY')
    if not access or not secret:
        sys.exit(
            f'error: set {env_prefix}_ACCESS_KEY and {env_prefix}_SECRET_KEY in the environment '
            '(Security Center API keys for a user who can view the scans you want to sweep).'
        )
    url = url or os.environ.get(f'{env_prefix}_URL')
    if not url:
        sys.exit(f'error: set {env_prefix}_URL or pass --url. Security Center has no default address.')
    return TenableSC(
        url=url.rstrip('/'),
        access_key=access,
        secret_key=secret,
        ssl_verify=verify,
        vendor='Tenable Community',
        product='tenable-scan-sweep',
        build=VERSION,
    )


def _sc_items(response: dict) -> list[dict]:
    """Items from an SC list response, which is either a list or {usable, manageable}."""
    body = response.get('response')
    if isinstance(body, dict):
        items = (body.get('usable') or []) + (body.get('manageable') or [])
    else:
        items = body or []
    return list({str(i.get('id')): i for i in items if isinstance(i, dict)}.values())


def _sc_list_members(asset: dict) -> list[str]:
    fields = asset.get('typeFields') or {}
    members = []
    for key in ('definedIPs', 'definedDNSNames'):
        for source in (fields, asset):
            if isinstance(source.get(key), str):
                members += split_targets(source[key])
    return list(dict.fromkeys(members))


def _sc_asset_lists(sc, errors: list[dict]) -> dict[str, dict]:
    lists = {}
    for asset in _sc_items(sc.get('asset', params={'fields': 'id,name,type,typeFields'}).json()):
        if asset.get('type') in SC_LITERAL_LIST_TYPES and not asset.get('typeFields'):
            # The list endpoint doesn't always include typeFields; read the list itself.
            try:
                asset = sc.get(f'asset/{int(asset["id"])}', params={'fields': 'id,name,type,typeFields,definedDNSNames'}).json()['response']
            except Exception as err:  # noqa: BLE001
                errors.append({'scan_id': None, 'name': f'asset list {asset.get("id")}', 'error': type(err).__name__})
        lists[str(asset['id'])] = {
            'name': asset.get('name'),
            'type': asset.get('type'),
            'members': _sc_list_members(asset),
            # A literal list with no members (or one that couldn't be read) has unknown
            # membership, like a rule-based list: report it as unresolved, not empty.
            'rule_based': asset.get('type') not in SC_LITERAL_LIST_TYPES or not _sc_list_members(asset),
        }
    return lists


def resolve_rule_based_lists(sc, lists: dict[str, dict], list_ids: Iterable[str], errors: list[dict]) -> int:
    """
    Read the current members of rule-based asset lists (dynamic, combination…) from their
    viewableIPs, one list at a time: the API warns that requesting viewableIPs for every list
    at once can be slow. A list type that doesn't report members stays unresolved.
    """
    resolved_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    count = 0
    for list_id in sorted(set(list_ids)):
        listed = lists.get(list_id)
        if not listed or not listed.get('rule_based'):
            continue
        try:
            detail = sc.get(f'asset/{int(list_id)}', params={'fields': 'id,name,type,viewableIPs'}).json()['response']
        except Exception as err:  # noqa: BLE001
            errors.append({'scan_id': None, 'name': f'asset list {list_id} members', 'error': type(err).__name__})
            continue
        viewable = detail.get('viewableIPs')
        if not isinstance(viewable, list):
            continue
        members = []
        for entry in viewable:
            if isinstance(entry, dict):
                # Hosts tracked by UUID are listed as '<host uuid>|<address>', and the
                # address can be empty.
                members += [a for t in split_targets(entry.get('ipList')) if (a := t.rsplit('|', 1)[-1])]
        listed.update(members=list(dict.fromkeys(members)), resolved=True, resolved_at=resolved_at)
        count += 1
    return count


def _sc_windows(sc, inventory: dict) -> list[dict]:
    """Freeze windows, or blackout windows on older SC versions, as exclusions."""
    from tenable.errors import APIError

    try:
        items = _sc_items(sc.get('freeze', params={'fields': SC_WINDOW_FIELDS}).json())
    except APIError:
        items = _sc_items(sc.get('blackout', params={'fields': SC_WINDOW_FIELDS}).json())
    out = []
    for win in items:
        members, unresolved = split_targets(win.get('ipList')), []
        for ref in win.get('assets') or []:
            listed = inventory['target_groups'].get(str(ref.get('id'))) or {}
            if listed.get('rule_based') and not listed.get('resolved'):
                unresolved.append(listed.get('name') or str(ref.get('id')))
            else:
                members += listed.get('members', [])
        repo = win.get('repository') or {}
        out.append(
            {
                'id': win.get('id'),
                'name': win.get('name'),
                'members': members,
                'all_ips': str(win.get('allIPs')).lower() == 'true',
                'unresolved_lists': unresolved,
                # A disabled freeze window doesn't apply at all (unlike a VM exclusion
                # with no schedule, which always applies).
                'disabled': str(win.get('enabled')).lower() != 'true',
                'schedule_enabled': True,
                'rrules': win.get('repeatRule'),
                'network_id': str(repo['id']) if repo.get('id') not in (None, '', -1, '-1') else None,
            }
        )
    return out


def normalize_sc_scan(scan: dict, inventory: dict, templates: dict[str, str]) -> dict:
    zone = scan.get('zone') or {}
    zone_id = str(zone.get('id', ''))
    zone_name = zone.get('name') or ('All zones (automatic)' if zone_id in ('', '0', '-1') else zone_id)
    inventory['scanners'][zone_id or '0'] = {'name': zone_name, 'type': 'zone', 'status': None}
    repo = scan.get('repository') or {}
    repo_id = str(repo.get('id')) if repo.get('id') not in (None, '', -1, '-1') else None
    if repo_id:
        inventory['networks'][repo_id] = repo.get('name')
    policy = scan.get('policy') or {}
    if policy.get('id'):
        inventory['policies'][str(policy['id'])] = policy.get('name')
    sched = scan.get('schedule') or {}
    sc_type = sched.get('type')
    enabled = sc_type in SC_SCHEDULED_TYPES and str(sched.get('enabled', 'true')).lower() == 'true'
    if scan.get('type') == 'plugin':
        plugin = scan.get('plugin') or {}
        template = 'Single plugin scan' + (f" ({plugin.get('name')})" if plugin.get('name') else '')
    else:
        template = templates.get(str(policy.get('id'))) or policy.get('name')
    owner = scan.get('owner') or {}
    return {
        'id': scan.get('id'),
        'schedule_uuid': scan.get('uuid'),
        'name': scan.get('name'),
        'type': scan.get('type'),
        'template': template,
        'owner': owner.get('username'),
        'folder_id': None,
        'status': scan.get('status'),
        'enabled': enabled,
        'has_triggers': False,
        'created': scan.get('createdTime'),
        'modified': scan.get('modifiedTime'),
        'policy': {'id': policy.get('id'), 'name': policy.get('name')} if policy.get('id') else None,
        'scanner': {'id': zone_id or '0', 'name': zone_name, 'type': 'zone'},
        'network': {'uuid': repo_id, 'name': repo.get('name')} if repo_id else None,
        'targets': {
            'text': split_targets(scan.get('ipList')),
            'file_targets': False,
            'target_groups': [str(a.get('id')) for a in scan.get('assets') or [] if isinstance(a, dict)],
            'tags': [],
            'tag_mode': None,
            'tag_ip_selection': None,
            'agent_groups': [],
        },
        'schedule': {
            'enabled': enabled,
            'rrules': sched.get('repeatRule') if sc_type == 'ical' else None,
            'starttime': sched.get('start'),
            'timezone': None,
            'agent_scan_launch_type': None,
            'triggers': 0,
            'sc_type': sc_type,
            'dependent': (sched.get('dependent') or {}).get('name'),
        },
        'credentials': [
            {
                'category': c.get('type') or 'credential',
                'type': c.get('type') or 'credential',
                'managed': True,
                'source': 'scan',
                'id': c.get('id'),
                'summary': c.get('name'),
            }
            for c in scan.get('credentials') or []
            if isinstance(c, dict)
        ],
        'compliance_audits': 0,
    }


def collect_sc(args: argparse.Namespace) -> None:
    from tenable.errors import APIError

    verify: bool | str = args.ca_bundle or (not args.insecure)
    sc = connect_sc(args.env_prefix or 'TSC', args.url, verify)
    host = urlparse(str(sc._url)).hostname or 'securitycenter'
    snapshot_path = Path(args.snapshot) if args.snapshot else default_snapshot_path(host, args.env_prefix)
    errors: list[dict] = []
    inventory: dict[str, dict] = {k: {} for k in ('agent_groups', 'tags', 'target_groups', 'scanners', 'networks', 'policies')}
    inventory['target_groups'] = _sc_asset_lists(sc, errors)
    templates: dict[str, str] = {}
    try:
        for pol in _sc_items(sc.get('policy', params={'fields': 'id,name,policyTemplate'}).json()):
            templates[str(pol.get('id'))] = (pol.get('policyTemplate') or {}).get('name') or pol.get('name')
    except Exception as err:  # noqa: BLE001
        errors.append({'scan_id': None, 'name': 'policies', 'error': type(err).__name__})
    try:
        scans = _sc_items(sc.get('scan', params={'fields': SC_SCAN_FIELDS}).json())
    except APIError as err:
        if err.code == 401:
            sys.exit('error: Security Center rejected the API keys (401). Check the access and secret keys.')
        if err.code == 403:
            sys.exit(
                'error: Security Center refused to list scans (403). Administrator accounts '
                "can't see scans; use API keys for an organization user."
            )
        raise
    log(f'Listed {len(scans)} scans and {len(inventory["target_groups"])} asset lists')
    meta: dict[str, Any] = {'listed': len(scans)}
    if getattr(args, 'assets', False):
        used = {str(a.get('id')) for scan in scans for a in scan.get('assets') or [] if isinstance(a, dict)}
        rule_based_used = [i for i in used if (inventory['target_groups'].get(i) or {}).get('rule_based')]
        log(f'Reading current members of {len(rule_based_used)} rule-based asset lists…')
        meta['rule_lists_resolved'] = resolve_rule_based_lists(sc, inventory['target_groups'], rule_based_used, errors)
        meta['rule_lists_used'] = len(rule_based_used)
    records = []
    for scan in scans:
        try:
            records.append(normalize_sc_scan(scan, inventory, templates))
        except Exception as err:  # noqa: BLE001
            errors.append({'scan_id': scan.get('id'), 'name': scan.get('name'), 'error': f'unexpected configuration format ({type(err).__name__})'})
    try:
        exclusions = _sc_windows(sc, inventory)
    except Exception as err:  # noqa: BLE001
        exclusions = []
        errors.append({'scan_id': None, 'name': 'freeze windows', 'error': type(err).__name__})
    write_snapshot(snapshot_path, 'sc', host, meta, records, inventory, exclusions, errors)


def write_snapshot(path: Path, platform: str, host: str, meta: dict, records: list[dict], inventory: dict, exclusions: list[dict], errors: list[dict], asset_index: dict | None = None) -> None:
    snapshot = {
        'tool': 'tenable-scan-sweep',
        'version': VERSION,
        'platform': platform,
        'collected_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
        'container': host,
        'listing': meta,
        'scans': sorted(records, key=lambda r: (str(r['name']).lower(), str(r['id']))),
        'inventory': inventory,
        'exclusions': exclusions,
        'errors': errors,
    }
    if asset_index:
        snapshot['asset_index'] = asset_index
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create the file owner-only from the start; it holds internal network information.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)  # O_CREAT's mode doesn't apply to a file that already exists
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(snapshot, fh, indent=1)
    trashed = f', skipped {meta["trashed_skipped"]} in the trash' if meta.get('trashed_skipped') else ''
    log(f'Wrote {len(records)} scans{trashed}, {len(exclusions)} exclusions, {len(errors)} errors to {path}')


def _norm_uuid(value: Any) -> str:
    return re.sub(r'[^0-9a-f]', '', str(value or '').lower())


def build_asset_index(tio, errors: list[dict]) -> dict:
    """
    Optional asset and agent index, so `find` can tell which tags an address carries and
    which agent groups its agent is in. One asset export (v1, which includes identifiers and
    tags) plus a paged read of the agent list.
    """
    assets = []
    # Don't adopt another integration's running export: the cleanup below cancels the job.
    iterator = tio.exports.assets(chunk_size=4000, adopt_existing=False)
    try:
        for asset in iterator:
            assets.append(
                {
                    'id': asset.get('id'),
                    'ipv4s': asset.get('ipv4s') or [],
                    'ipv6s': asset.get('ipv6s') or [],
                    'names': sorted({n.lower().rstrip('.') for key in ('fqdns', 'hostnames', 'netbios_names') for n in asset.get(key) or []}),
                    'tags': sorted({f"{t.get('key')}:{t.get('value')}" for t in asset.get('tags') or [] if t.get('key')}),
                    'agent_uuid': _norm_uuid(asset.get('agent_uuid')) or None,
                }
            )
    finally:
        try:
            if tio.exports.status('assets', iterator.uuid).get('status') not in ('FINISHED', 'CANCELLED', 'ERROR'):
                tio.exports.cancel('assets', iterator.uuid)
        except Exception as err:  # noqa: BLE001
            errors.append({'scan_id': None, 'name': 'asset export cleanup', 'error': type(err).__name__})
    try:
        agents, _ = _paged(tio, 'scanners/null/agents', 'agents')
    except Exception as err:  # noqa: BLE001 - keep the assets; agent scans stay unresolved
        agents = []
        errors.append({'scan_id': None, 'name': 'agent list', 'error': f'{type(err).__name__}: {getattr(err, "code", "")}'.strip()})
    return {
        'collected_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
        'assets': assets,
        'agents': [
            {
                'uuid': _norm_uuid(a.get('uuid')),
                'name': (a.get('name') or '').lower(),
                'ip': a.get('ip'),
                # Scans reference agent groups by UUID and agents by numeric ID, so match on names.
                'groups': sorted({str(g.get('name')).lower() for g in a.get('groups') or [] if isinstance(g, dict) and g.get('name')}),
            }
            for a in agents
        ],
    }


def collect(args: argparse.Namespace) -> None:
    if getattr(args, 'platform', 'vm') == 'sc':
        collect_sc(args)
        return
    tio = connect(args.env_prefix or 'TIO', args.url)
    host = urlparse(str(tio._url)).hostname or 'tenable'
    snapshot_path = Path(args.snapshot) if args.snapshot else default_snapshot_path(host, args.env_prefix)
    from tenable.errors import APIError

    try:
        scans, meta = list_all_scans(tio)
    except APIError as err:
        if err.code in (401, 403):
            prefix = args.env_prefix or 'TIO'
            sys.exit(f'error: Tenable VM refused to list scans ({err.code}). Check {prefix}_ACCESS_KEY, '
                     f"{prefix}_SECRET_KEY and the user's role.")
        raise
    log(f'Listed {meta["listed"]} scans' + (f' of {meta["reported_total"]} reported' if meta.get('paginated') else '')
        + (f'; skipping {meta["trashed_skipped"]} in the trash' if meta.get('trashed_skipped') else ''))
    inventory: dict[str, dict] = {k: {} for k in ('agent_groups', 'tags', 'target_groups', 'scanners', 'networks', 'policies')}
    records, errors = [], []

    def fetch(summary: dict) -> tuple[dict, dict | None, str | None]:
        try:
            return summary, tio.get(f'editor/scan/{int(summary["id"])}').json(), None
        except Exception as err:  # noqa: BLE001 - report per scan and keep going
            return summary, None, f'{type(err).__name__}: {getattr(err, "code", "")}'.strip()

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(fetch, s) for s in scans]
        for n, future in enumerate(as_completed(futures), start=1):
            summary, editor, error = future.result()
            if editor is not None:
                try:
                    records.append(normalize_scan(summary, editor, inventory, args.include_credential_summaries))
                except Exception as err:  # noqa: BLE001 - one odd configuration shouldn't lose the rest
                    error = f'unexpected configuration format ({type(err).__name__})'
            if error:
                errors.append({'scan_id': summary.get('id'), 'name': summary.get('name'), 'error': error})
            if n % 50 == 0:
                log(f'  {n}/{len(scans)} scan configurations read')

    # Scans built from a user-defined policy can keep their credentials in the policy,
    # so read each referenced policy once and attach its credentials to those scans.
    policy_ids = sorted({str(r['policy']['id']) for r in records if r['policy']})
    policy_creds: dict[str, list[dict]] = {}
    for pid in policy_ids:
        try:
            policy_creds[pid] = parse_credentials(tio.get(f'editor/policy/{int(pid)}').json(), args.include_credential_summaries, source='policy')
        except Exception as err:  # noqa: BLE001
            errors.append({'scan_id': None, 'name': f'policy {pid}', 'error': f'{type(err).__name__}: {getattr(err, "code", "")}'.strip()})
    for record in records:
        if record['policy']:
            record['credentials'] += policy_creds.get(str(record['policy']['id']), [])
    if policy_ids:
        log(f'Read {len(policy_creds)} of {len(policy_ids)} scan policies for their credentials')

    try:
        exclusions = _list_exclusions(tio)
    except Exception as err:  # noqa: BLE001
        exclusions = []
        errors.append({'scan_id': None, 'name': 'exclusions', 'error': type(err).__name__})

    asset_index = None
    if getattr(args, 'assets', False):
        log('Exporting assets and reading agents for the asset index…')
        try:
            asset_index = build_asset_index(tio, errors)
            log(f'Indexed {len(asset_index["assets"])} assets and {len(asset_index["agents"])} agents')
        except Exception as err:  # noqa: BLE001
            errors.append({'scan_id': None, 'name': 'asset index', 'error': f'{type(err).__name__}: {getattr(err, "code", "")}'.strip()})
    write_snapshot(snapshot_path, 'vm', host, meta, records, inventory, exclusions, errors, asset_index)
    if meta.get('paginated') and meta['listed'] < meta['reported_total']:
        log(f'warning: read {meta["listed"]} of {meta["reported_total"]} scans the API reported; run collect again')


# --------------------------------------------------------------------------------------
# Snapshot helpers
# --------------------------------------------------------------------------------------


def default_snapshot_path(host: str, env_prefix: str | None = None) -> Path:
    """<host>.json, or <host>-<prefix>.json for a non-default --env-prefix, so two containers
    on one host (cloud.tenable.com, or one SC with two users) don't overwrite each other."""
    base = os.environ.get('SCAN_SWEEP_HOME') or Path.home() / '.cache' / 'tenable-scan-sweep'
    suffix = f'-{env_prefix.lower()}' if env_prefix and env_prefix not in ('TIO', 'TSC') else ''
    return Path(base) / f'{host}{suffix}.json'


def _is_snapshot(path: Path) -> bool:
    try:
        return json.loads(path.read_text(encoding='utf-8')).get('tool') == 'tenable-scan-sweep'
    except (OSError, ValueError, AttributeError):
        return False


def load_snapshot(path_arg: str | None) -> dict:
    if path_arg:
        path = Path(path_arg)
    else:
        base = Path(os.environ.get('SCAN_SWEEP_HOME') or Path.home() / '.cache' / 'tenable-scan-sweep')
        candidates = sorted(base.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True) if base.exists() else []
        candidates = [c for c in candidates if _is_snapshot(c)]
        if not candidates:
            sys.exit('error: no snapshot found. Run `scan_sweep.py collect` first.')
        path = candidates[0]
        if len(candidates) > 1:
            log(f'Using the newest snapshot, {path.name}; pass --snapshot to choose another.')
    snap = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(snap, dict) or snap.get('tool') != 'tenable-scan-sweep':
        sys.exit(f'error: {path} is not a tenable-scan-sweep snapshot.')
    snap['_path'] = str(path)
    for scan in snap['scans']:
        scan['_resolved'] = resolve_scan_targets(scan, snap)
    return snap


def snapshot_age_hours(snap: dict) -> float:
    collected = dt.datetime.fromisoformat(snap['collected_at'])
    return (dt.datetime.now(dt.timezone.utc) - collected).total_seconds() / 3600


def resolve_scan_targets(scan: dict, snap: dict) -> dict:
    """Expand a scan's text targets and target groups into intervals and hostnames."""
    entries = []
    for raw in scan['targets']['text']:
        entries.append(('text', None, parse_target(raw)))
    for group_id in scan['targets']['target_groups']:
        group = snap['inventory']['target_groups'].get(group_id) or {}
        for raw in group.get('members', []):
            entries.append(('target-group', group.get('name') or group_id, parse_target(raw)))
    intervals = merge_intervals(iv for _, _, p in entries for iv in p['intervals'])
    return {
        'entries': entries,
        'intervals': intervals,
        'hostnames': {p['hostname'] for _, _, p in entries if p['hostname']},
        'unknown': [p['raw'] for _, _, p in entries if p['kind'] == 'unknown'],
        'approximate': any(p.get('approximate') for _, _, p in entries),
    }


def scan_kind(scan: dict) -> str:
    if scan['targets']['agent_groups'] or scan['type'] == 'agent':
        return 'agent'
    if scan['type'] == 'pvs':
        return 'nnm'
    return 'network'


def schedule_text(scan: dict) -> str:
    sched = scan['schedule']
    if scan['schedule'].get('triggers'):
        return 'triggered'
    sc_type = sched.get('sc_type')
    if sc_type == 'dependent':
        return f"after '{sched.get('dependent')}'" if sched.get('dependent') else 'after another scan'
    if sc_type == 'rollover':
        return 'rollover'
    if sc_type == 'ical' and sched.get('enabled') and not sched.get('rrules'):
        return 'once'
    if not sched.get('enabled') or not sched.get('rrules'):
        return 'on demand'
    rrules = dict(part.split('=', 1) for part in str(sched['rrules']).split(';') if '=' in part)
    freq = rrules.get('FREQ', '?').lower()
    interval = rrules.get('INTERVAL', '1')
    when = f'every {interval} {freq}' if interval != '1' else freq
    if rrules.get('BYDAY'):
        when += f' ({rrules["BYDAY"]})'
    return when


DEFAULT_NETWORK = '00000000-0000-0000-0000-000000000000'


def network_key(scan: dict) -> str:
    return str((scan.get('network') or {}).get('uuid') or DEFAULT_NETWORK)


def network_name(scan: dict) -> str:
    net = scan.get('network') or {}
    return net.get('name') or ('Default' if network_key(scan) == DEFAULT_NETWORK else network_key(scan))


def tag_label(snap: dict, uuid: str) -> str:
    tag = snap['inventory']['tags'].get(uuid) or {}
    if tag:
        return f'{tag.get("category")}:{tag.get("value")}'
    return uuid


def name_of(mapping: dict, key: str) -> str:
    value = mapping.get(key)
    if isinstance(value, dict):
        value = value.get('name')
    return value or key


# --------------------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------------------

SELECTORS = ('tag', 'agent-group', 'target-group', 'asset-list', 'scanner', 'credential', 'policy', 'network', 'repository', 'zone', 'template', 'owner')


def _name_matches(query: str, value: str | None) -> bool:
    return bool(value) and query.lower() in str(value).lower()


def find_matches(snap: dict, query: str, asset_tags: list[str], asset_lists: Iterable[str] = ()) -> dict:
    selector, sep, rest = query.partition(':')
    if sep and selector.lower() in SELECTORS:
        return _find_by_selector(snap, selector.lower(), rest)
    parsed = parse_target(query)
    if parsed['kind'] in ('unknown', 'link6'):
        return {'query': query, 'error': 'not an IP, range, CIDR, hostname or selector', 'matches': []}
    q_intervals = merge_intervals(parsed['intervals'])
    q_host = parsed['hostname']
    wanted_tags = {t.lower() for t in asset_tags}
    wanted_lists = {name.lower() for name in asset_lists}
    group_word = 'asset list' if snap.get('platform') == 'sc' else 'target group'
    lists = snap['inventory']['target_groups']
    resolved_names = {str(v.get('name')): v.get('resolved_at') for v in lists.values() if v.get('resolved')}
    index = lookup_asset_index(snap, q_intervals, q_host)
    index_tags = {t.lower() for t in (index or {}).get('tags', [])}
    index_groups = set((index or {}).get('agent_groups', []))
    agent_group_names = {g: str(name_of(snap['inventory']['agent_groups'], g)).lower() for s_ in snap['scans'] for g in s_['targets']['agent_groups']}
    matches, tag_scans, list_scans = [], [], []
    unchecked: dict[str, int] = dict.fromkeys(
        ('uploaded target file', 'hostname/mask target (needs DNS)', 'hostname targets (IP query not resolved to names)', 'unparsed targets'), 0
    )
    for scan in snap['scans']:
        res = scan['_resolved']
        reasons = []
        if q_intervals:
            for source, group, p in res['entries']:
                shared = overlap_size(q_intervals, merge_intervals(p['intervals'])) if p['intervals'] else 0
                if shared:
                    where = f"{group_word} '{group}'" if source == 'target-group' else 'target'
                    note = f' ({shared} shared addresses)' if address_count(q_intervals) > 1 else ''
                    if p.get('approximate'):
                        note += ' (approximate: very large octet range, bounded)'
                    if source == 'target-group' and group in resolved_names:
                        note += f' (rule-based list; members as of {resolved_names[group]})'
                    reasons.append(f'{where} {p["raw"]}{note}')
        if q_host:
            for source, group, p in res['entries']:
                how = host_match(q_host, p['hostname'])
                if not how:
                    continue
                where = f"{group_word} '{group}'" if source == 'target-group' else 'target'
                reasons.append(f'{where} {p["raw"]}' + (' (possible: same short name)' if how == 'possible' else ''))
        for uuid in scan['targets']['tags']:
            label = tag_label(snap, uuid)
            if label.lower() in wanted_tags:
                reasons.append(f'tag {label}')
            elif label.lower() in index_tags:
                reasons.append(f'tag {label} (from asset index)')
        for g in scan['targets']['agent_groups']:
            if agent_group_names.get(g) in index_groups:
                reasons.append(f"agent group '{name_of(snap['inventory']['agent_groups'], g)}' (from asset index)")
        rule_lists = [lists[g] for g in scan['targets']['target_groups'] if (lists.get(g) or {}).get('rule_based') and not lists[g].get('resolved')]
        for listed in rule_lists:
            if str(listed.get('name')).lower() in wanted_lists:
                reasons.append(f"asset list '{listed.get('name')}' (membership supplied)")
        if reasons:
            matches.append(_match_row(scan, reasons))
            continue
        if scan['targets']['tags'] and not (index and index['assets_matched']):
            tag_scans.append(scan)
        if rule_lists:
            list_scans.append((scan, rule_lists))
        # Scans whose targets can't be checked offline might still include this target.
        kinds = {p['kind'] for _, _, p in res['entries']}
        if scan['targets']['file_targets']:
            unchecked['uploaded target file'] += 1
        if 'hostname-subnet' in kinds:
            unchecked['hostname/mask target (needs DNS)'] += 1
        if q_intervals and 'hostname' in kinds:
            unchecked['hostname targets (IP query not resolved to names)'] += 1
        if res['unknown']:
            unchecked['unparsed targets'] += 1
    exclusions, maybe_excluded = [], []
    for ex in snap.get('exclusions', []):
        if ex.get('disabled'):
            continue
        ex_intervals = merge_intervals(iv for m in ex['members'] for iv in parse_target(m)['intervals'])
        hit = ex.get('all_ips') or (q_intervals and overlap_size(q_intervals, ex_intervals)) or (
            q_host and any(parse_target(m)['hostname'] == q_host for m in ex['members'])
        )
        if hit:
            network = ex.get('network_id')
            exclusions.append({
                'name': ex['name'],
                'schedule_enabled': ex.get('schedule_enabled'),
                'network': snap['inventory']['networks'].get(str(network), network) if network else None,
            })
        elif ex.get('unresolved_lists'):
            maybe_excluded.append({'name': ex['name'], 'unresolved_lists': ex['unresolved_lists']})
    unresolved = sorted({tag_label(snap, u) for s in tag_scans for u in s['targets']['tags']})
    return {
        'query': query,
        'kind': parsed['kind'],
        'matches': matches,
        'excluded_by': exclusions,
        'possibly_excluded_by': maybe_excluded,
        'exclusions_collected': not any(e.get('name') in ('exclusions', 'freeze windows') for e in snap.get('errors', [])),
        'unresolved_tag_scans': len(tag_scans),
        'unresolved_tags': unresolved,
        'unresolved_list_scans': len(list_scans),
        'unresolved_lists': sorted({str(item.get('name')) for _, rl in list_scans for item in rl}),
        'agent_scans_not_checked': 0 if index and (index['assets_matched'] or index['agents_matched']) else sum(1 for s in snap['scans'] if scan_kind(s) == 'agent'),
        'asset_index': index,
        'unchecked_scans': {k: v for k, v in unchecked.items() if v},
    }


def host_match(query: str | None, name: str | None) -> str | None:
    """'exact', 'possible' (the short names match and one side has no domain) or None."""
    if not query or not name:
        return None
    if query == name:
        return 'exact'
    if ('.' not in query or '.' not in name) and query.split('.')[0] == name.split('.')[0]:
        return 'possible'
    return None


def lookup_asset_index(snap: dict, q_intervals: list, q_host: str | None) -> dict | None:
    """Assets and agents in the snapshot's asset index that match an IP, range or hostname."""
    index = snap.get('asset_index')
    if not index or not (q_intervals or q_host):
        return None
    def name_hit(names: Iterable[str]) -> bool:
        return bool(q_host) and any(host_match(q_host, n) for n in names)
    assets = []
    for a in index['assets']:
        ips = merge_intervals(iv for ip in a['ipv4s'] + a['ipv6s'] for iv in parse_target(ip)['intervals'])
        if (q_intervals and ips and overlap_size(q_intervals, ips)) or name_hit(a['names']):
            assets.append(a)
    agent_ids = {a['agent_uuid'] for a in assets if a.get('agent_uuid')}
    agents = []
    for ag in index['agents']:
        ip_hit = q_intervals and ag.get('ip') and overlap_size(q_intervals, merge_intervals(parse_target(ag['ip'])['intervals']))
        if ag['uuid'] in agent_ids or ip_hit or name_hit([ag.get('name') or '']):
            agents.append(ag)
    return {
        'collected_at': index.get('collected_at'),
        'assets_matched': len(assets),
        'tags': sorted({t for a in assets for t in a['tags']}),
        'agents_matched': len(agents),
        'agent_groups': sorted({g for ag in agents for g in ag['groups']}),
    }


def _find_by_selector(snap: dict, selector: str, value: str) -> dict:
    inv = snap['inventory']
    matches = []
    for scan in snap['scans']:
        reasons = []
        t = scan['targets']
        if selector == 'tag':
            reasons = [f'tag {tag_label(snap, u)}' for u in t['tags'] if _tag_matches(value, tag_label(snap, u))]
        elif selector == 'agent-group':
            reasons = [f"agent group '{name_of(inv['agent_groups'], g)}'" for g in t['agent_groups'] if _name_matches(value, name_of(inv['agent_groups'], g))]
        elif selector in ('target-group', 'asset-list'):
            word = 'asset list' if snap.get('platform') == 'sc' else 'target group'
            reasons = [f"{word} '{name_of(inv['target_groups'], g)}'" for g in t['target_groups'] if _name_matches(value, name_of(inv['target_groups'], g))]
        elif selector in ('scanner', 'zone') and scan['scanner'] and _name_matches(value, scan['scanner'].get('name') or str(scan['scanner']['id'])):
            reasons = [f"scanner '{scan['scanner'].get('name')}'"]
        elif selector == 'credential':
            reasons = [
                f"{c['category']} / {c['type']}" + (f" ({c.get('summary')})" if c.get('managed') and c.get('summary') else '')
                for c in scan['credentials']
                if _name_matches(value, f"{c['category']} {c['type']} {c.get('summary') or ''}")
            ]
        elif selector == 'policy' and scan['policy'] and _name_matches(value, scan['policy'].get('name')):
            reasons = [f"policy '{scan['policy']['name']}'"]
        elif selector in ('network', 'repository') and scan['network'] and _name_matches(value, scan['network'].get('name')):
            word = 'repository' if snap.get('platform') == 'sc' else 'network'
            reasons = [f"{word} '{scan['network']['name']}'"]
        elif selector == 'template' and _name_matches(value, scan.get('template')):
            reasons = [f"template '{scan['template']}'"]
        elif selector == 'owner' and _name_matches(value, scan.get('owner')):
            reasons = [f"owner '{scan['owner']}'"]
        if reasons:
            matches.append(_match_row(scan, reasons))
    return {'query': f'{selector}:{value}', 'kind': selector, 'matches': matches}


def _tag_matches(query: str, label: str) -> bool:
    if ':' in query:
        return query.lower() == label.lower()
    return query.lower() in label.lower()


def _match_row(scan: dict, reasons: list[str]) -> dict:
    return {
        'id': scan['id'],
        'name': scan['name'],
        'kind': scan_kind(scan),
        'enabled': bool(scan['schedule'].get('enabled')),
        'schedule': schedule_text(scan),
        'scanner': (scan['scanner'] or {}).get('name'),
        'network': network_name(scan),
        'template': scan.get('template'),
        'matched_by': sorted(set(reasons)),
    }


def find_overlaps(snap: dict, include_disabled: bool, min_shared: int) -> list[dict]:
    scans = [
        s
        for s in snap['scans']
        if scan_kind(s) == 'network' and s['_resolved']['intervals'] and (include_disabled or s['schedule'].get('enabled'))
    ]
    pairs = []
    for a, b in itertools.combinations(scans, 2):
        # Networks let separate sites reuse the same private ranges, so only compare
        # scans in the same network.
        if network_key(a) != network_key(b):
            continue
        ia, ib = a['_resolved']['intervals'], b['_resolved']['intervals']
        shared = overlap_size(ia, ib)
        if shared < min_shared:
            continue
        na, nb = address_count(ia), address_count(ib)
        pairs.append(
            {
                'scan_a': a['name'],
                'scan_a_id': a['id'],
                'scan_b': b['name'],
                'scan_b_id': b['id'],
                'shared_addresses': shared,
                'pct_of_a': round(100 * shared / na, 1),
                'pct_of_b': round(100 * shared / nb, 1),
                'identical': ia == ib,
                'same_template': a.get('template') == b.get('template'),
                'network': network_name(a),
                'approximate': a['_resolved']['approximate'] or b['_resolved']['approximate'],
                'schedules': f'{schedule_text(a)} / {schedule_text(b)}',
            }
        )
    return sorted(pairs, key=lambda p: (-p['identical'], -p['shared_addresses']))


def audit(snap: dict) -> list[dict]:
    findings = []
    inv = snap['inventory']

    def add(severity: str, check: str, scan: dict | None, detail: str) -> None:
        findings.append(
            {
                'severity': severity,
                'check': check,
                'scan': scan['name'] if scan else '',
                'scan_id': scan['id'] if scan else '',
                'detail': detail,
            }
        )

    used = {'agent_groups': set(), 'target_groups': set(), 'tags': set(), 'scanners': set()}
    for scan in snap['scans']:
        t, res, kind = scan['targets'], scan['_resolved'], scan_kind(scan)
        used['agent_groups'].update(t['agent_groups'])
        used['target_groups'].update(t['target_groups'])
        used['tags'].update(t['tags'])
        if scan['scanner']:
            used['scanners'].add(str(scan['scanner']['id']))
        has_targets = t['text'] or t['target_groups'] or t['tags'] or t['file_targets'] or t['agent_groups']
        if kind == 'network' and not has_targets:
            scheduled = scan['schedule'].get('enabled') or scan['schedule'].get('triggers')
            add('warn' if scheduled else 'info', 'no-targets', scan,
                'No text targets, target groups, tags or target file.' + ('' if scheduled else ' The scan has no enabled schedule.'))
        if kind == 'agent' and not t['agent_groups']:
            add('warn', 'no-agent-groups', scan, 'Agent scan with no agent groups.')
        if res['unknown']:
            add('warn', 'unparsed-targets', scan, 'Targets not in a recognized format: ' + ', '.join(res['unknown'][:10]))
        hs = [p['raw'] for _, _, p in res['entries'] if p['kind'] == 'hostname-subnet']
        if hs:
            add('info', 'dns-dependent-subnet', scan, 'Subnet depends on DNS resolution at scan time: ' + ', '.join(hs[:5]))
        if res['approximate']:
            add('info', 'approximate-targets', scan, 'Octet-range targets were approximated by a bounding range.')
        size = address_count(res['intervals'])
        if size > LARGE_TARGET_ADDRESSES:
            add('info', 'large-target', scan, f'{size:,} addresses in text targets and target groups.')
        if t['target_groups'] and snap.get('platform', 'vm') == 'vm':
            names = ', '.join(name_of(inv['target_groups'], g) for g in t['target_groups'])
            add('info', 'target-groups', scan, f'Uses target groups ({names}); VM recommends tags instead.')
        template = (scan.get('template') or '').lower()
        if kind == 'network' and template in CREDENTIALED_TEMPLATES and not scan['credentials']:
            add('warn', 'uncredentialed', scan, f"'{scan.get('template')}' scan with no credentials; results will be limited to a remote view.")
        if not scan['schedule'].get('enabled') and not scan['schedule'].get('triggers'):
            add('info', 'on-demand', scan, 'No enabled schedule; runs only when launched.')
    for pair in find_overlaps(snap, include_disabled=False, min_shared=1):
        if pair['identical']:
            add('warn', 'duplicate-targets', None, f"'{pair['scan_a']}' and '{pair['scan_b']}' scan identical targets ({pair['shared_addresses']:,} addresses, {pair['schedules']}).")
    sc = snap.get('platform') == 'sc'
    names_by_key = (('agent_groups', 'agent group'), ('target_groups', 'asset list' if sc else 'target group'), ('scanners', 'scanner'))
    for key, label in names_by_key:
        if sc and key == 'scanners':
            continue  # zones are only known from scans that use them
        if sc and key == 'target_groups':
            # SC asset lists also drive analysis, dashboards and access, so one that no
            # scan uses isn't a problem on its own. Report the count, not each list.
            unused = len(set(inv[key]) - used[key])
            if unused:
                add('info', 'asset-lists-not-scan-targets', None, f'{unused} of {len(inv[key])} asset lists are not used by any scan.')
            continue
        for item_id in sorted(set(inv[key]) - used[key]):
            name = name_of(inv[key], item_id)
            if key == 'scanners' and (inv[key][item_id] or {}).get('type') == 'pool':
                continue
            add('info', f'unused-{key.replace("_", "-")[:-1]}', None, f"{label} '{name}' isn't referenced by any scan.")
    unused_tags = len(set(inv['tags']) - used['tags'])
    if unused_tags:
        add('info', 'tags-not-scan-targets', None, f'{unused_tags} of {len(inv["tags"])} tags offered as targets are not used by any scan.')
    for err in snap.get('errors', []):
        add('warn', 'collect-error', None, f"Couldn't read '{err.get('name')}' ({err.get('scan_id')}): {err.get('error')}")
    order = {'warn': 0, 'info': 1}
    return sorted(findings, key=lambda f: (order[f['severity']], f['check'], str(f['scan'])))


def credential_usage(snap: dict) -> dict:
    by_type: dict[str, list[str]] = {}
    managed: dict[str, list[str]] = {}
    for scan in snap['scans']:
        for c in scan['credentials']:
            by_type.setdefault(f"{c['category']} / {c['type']}", []).append(scan['name'])
            if c.get('managed'):
                managed.setdefault(c.get('summary') or c.get('id') or 'managed', []).append(scan['name'])
    missing = [
        {'id': s['id'], 'name': s['name'], 'template': s.get('template'), 'schedule': schedule_text(s)}
        for s in snap['scans']
        if scan_kind(s) == 'network' and not s['credentials'] and (s.get('template') or '').lower() in CREDENTIALED_TEMPLATES
    ]
    return {
        'by_type': {k: sorted(set(v)) for k, v in sorted(by_type.items())},
        'managed': {k: sorted(set(v)) for k, v in sorted(managed.items())},
        'uncredentialed_scans': missing,
    }


def find_scan(snap: dict, ident: str) -> list[dict]:
    by_id = [s for s in snap['scans'] if str(s['id']) == ident] if ident.isdigit() else []
    if by_id:
        return by_id
    exact = [s for s in snap['scans'] if str(s['name']).lower() == ident.lower()]
    return exact or [s for s in snap['scans'] if ident.lower() in str(s['name']).lower()]


def describe_scan(snap: dict, scan: dict) -> dict:
    inv, t = snap['inventory'], scan['targets']
    out = {k: v for k, v in scan.items() if not k.startswith('_')}
    out['schedule_summary'] = schedule_text(scan)
    out['targets'] = dict(t)
    out['targets']['target_groups'] = [
        {'name': name_of(inv['target_groups'], g), 'members': (inv['target_groups'].get(g) or {}).get('members', [])}
        for g in t['target_groups']
    ]
    out['targets']['tags'] = [tag_label(snap, u) for u in t['tags']]
    out['targets']['agent_groups'] = [name_of(inv['agent_groups'], g) for g in t['agent_groups']]
    out['targets']['address_count'] = address_count(scan['_resolved']['intervals'])
    return out


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------


def log(message: str) -> None:
    print(message, file=sys.stderr)


def md_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return '_None._\n'
    def cell(value: Any) -> str:
        if isinstance(value, list):
            value = '; '.join(str(v) for v in value)
        return str('' if value is None else value).replace('|', '\\|').replace('\n', ' ')
    lines = ['| ' + ' | '.join(columns) + ' |', '|' + '---|' * len(columns)]
    lines += ['| ' + ' | '.join(cell(r.get(c)) for c in columns) + ' |' for r in rows]
    return '\n'.join(lines) + '\n'


def csv_text(rows: list[dict], columns: list[str]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction='ignore', lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({c: _csv_safe('; '.join(map(str, row[c])) if isinstance(row.get(c), list) else row.get(c)) for c in columns})
    return buf.getvalue()


def _csv_safe(value: Any) -> Any:
    # Scan names are user-controlled; stop spreadsheets from treating them as formulas.
    if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def emit(fmt: str, payload: Any, markdown: str, rows: list[dict] | None = None, columns: list[str] | None = None) -> None:
    if fmt == 'json':
        print(json.dumps(payload, indent=1, default=str))
    elif fmt == 'csv' and rows is not None and columns:
        sys.stdout.write(csv_text(rows, columns))
    else:
        sys.stdout.write(markdown)


def header(snap: dict) -> str:
    age = snapshot_age_hours(snap)
    note = f' **Stale: {age:.0f} hours old; run `collect` to refresh.**' if age > STALE_HOURS else ''
    product = 'Security Center' if snap.get('platform') == 'sc' else 'Vulnerability Management'
    return f'_Snapshot of {len(snap["scans"])} {product} scans from {snap["container"]}, collected {snap["collected_at"]}._{note}\n\n'


MATCH_COLUMNS = ['id', 'name', 'kind', 'enabled', 'schedule', 'scanner', 'network', 'template', 'matched_by']


def cmd_find(args: argparse.Namespace) -> None:
    snap = load_snapshot(args.snapshot)
    results = [find_matches(snap, q, args.asset_tag or [], args.asset_list or []) for q in args.targets]
    parts = [header(snap)]
    for r in results:
        parts.append(f'## {r["query"]}\n\n')
        if r.get('error'):
            parts.append(f'{r["error"]}\n\n')
            continue
        parts.append(f'{len(r["matches"])} scan(s) target this.\n\n' + md_table(r['matches'], MATCH_COLUMNS) + '\n')
        if r.get('excluded_by'):
            parts.append('**Excluded by:** ' + ', '.join(
                f"'{e['name']}'" + ('' if e['schedule_enabled'] else ' (always)') + (f" in network '{e['network']}'" if e.get('network') else '')
                for e in r['excluded_by']) + '\n\n')
        if r.get('possibly_excluded_by'):
            parts.append('**Possibly excluded by:** ' + ', '.join(
                f"'{e['name']}' (uses unresolved asset lists: {', '.join(e['unresolved_lists'])})"
                for e in r['possibly_excluded_by']) + '\n\n')
        if not r.get('exclusions_collected', True):
            parts.append("**Exclusions weren't collected** (see `audit`), so this can't say whether the address is excluded.\n\n")
        if r.get('unchecked_scans'):
            parts.append('Not checked offline, and may also target this: ' + ', '.join(f'{v} scan(s) with {k}' for k, v in r['unchecked_scans'].items()) + '.\n\n')
        idx = r.get('asset_index')
        if idx and (idx['assets_matched'] or idx['agents_matched']):
            parts.append(
                f"Resolved from the asset index (collected {idx['collected_at']}): {idx['assets_matched']} asset(s) with tags "
                + (', '.join(idx['tags']) or 'none') + f", {idx['agents_matched']} agent(s) in groups " + (', '.join(idx['agent_groups']) or 'none') + '.\n\n'
            )
        elif idx:
            parts.append(f"Not found in the asset index (collected {idx['collected_at']}), so its tags and agent groups are unknown.\n\n")
        if r.get('unresolved_tag_scans'):
            parts.append(
                f'{r["unresolved_tag_scans"]} more scan(s) target by tag and may include this asset: '
                + ', '.join(r['unresolved_tags'][:30])
                + '. Rerun with `--asset-tag Category:Value` for each tag the asset has.\n\n'
            )
        if r.get('unresolved_list_scans'):
            parts.append(
                f'{r["unresolved_list_scans"]} more scan(s) use rule-based asset lists that may include this asset: '
                + ', '.join(r['unresolved_lists'][:30])
                + '. Rerun with `--asset-list Name` for each of these lists the asset belongs to.\n\n'
            )
        if r.get('agent_scans_not_checked'):
            parts.append(f'{r["agent_scans_not_checked"]} agent scan(s) target agent groups, not addresses; check the agent\'s groups separately.\n\n')
    rows = [dict(m, query=r['query']) for r in results for m in r.get('matches', [])]
    emit(args.format, results, ''.join(parts), rows, ['query'] + MATCH_COLUMNS)


def cmd_overlaps(args: argparse.Namespace) -> None:
    snap = load_snapshot(args.snapshot)
    pairs = find_overlaps(snap, args.include_disabled, args.min_shared)
    cols = ['scan_a', 'scan_b', 'network', 'shared_addresses', 'pct_of_a', 'pct_of_b', 'identical', 'same_template', 'approximate', 'schedules']
    scope = 'all' if args.include_disabled else 'scheduled'
    md = header(snap) + f'{len(pairs)} pair(s) of {scope} network scans share target addresses.\n\n' + md_table(pairs[: args.limit], cols)
    if len(pairs) > args.limit:
        md += f'\n_Showing {args.limit} of {len(pairs)}; use --limit or --format csv for the rest._\n'
    emit(args.format, pairs, md, pairs, cols)


def cmd_audit(args: argparse.Namespace) -> None:
    snap = load_snapshot(args.snapshot)
    findings = audit(snap)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f['check']] = counts.get(f['check'], 0) + 1
    summary = ', '.join(f'{k}: {v}' for k, v in sorted(counts.items())) or 'no findings'
    cols = ['severity', 'check', 'scan', 'scan_id', 'detail']
    emit(args.format, findings, header(snap) + f'**Summary:** {summary}\n\n' + md_table(findings, cols), findings, cols)


def cmd_credentials(args: argparse.Namespace) -> None:
    snap = load_snapshot(args.snapshot)
    usage = credential_usage(snap)
    md = header(snap) + '## Credential types\n\n'
    md += md_table([{'credential': k, 'scans': len(v)} for k, v in usage['by_type'].items()], ['credential', 'scans'])
    md += '\n## Managed credentials\n\n'
    md += md_table([{'credential': k, 'scans': len(v), 'scan names': v} for k, v in usage['managed'].items()], ['credential', 'scans', 'scan names'])
    md += '\n## Credentialed templates with no credentials\n\n'
    md += md_table(usage['uncredentialed_scans'], ['id', 'name', 'template', 'schedule'])
    emit(args.format, usage, md, usage['uncredentialed_scans'], ['id', 'name', 'template', 'schedule'])


def cmd_show(args: argparse.Namespace) -> None:
    snap = load_snapshot(args.snapshot)
    found = find_scan(snap, args.scan)
    if not found:
        sys.exit(f"error: no scan matches '{args.scan}'")
    described = [describe_scan(snap, s) for s in found[:10]]
    md = header(snap)
    if len(found) > 1:
        md += f'{len(found)} scans match; showing up to 10. Use the scan ID for one.\n\n'
    for d in described:
        md += f'## {d["name"]} (id {d["id"]})\n\n```json\n{json.dumps(d, indent=1, default=str)}\n```\n\n'
    emit(args.format, described, md)


LIST_COLUMNS = ['id', 'name', 'kind', 'template', 'enabled', 'schedule', 'scanner', 'network', 'text_targets', 'target_groups', 'tags', 'agent_groups', 'addresses', 'credentials', 'owner']


def cmd_list(args: argparse.Namespace) -> None:
    snap = load_snapshot(args.snapshot)
    inv = snap['inventory']
    rows = []
    for s in snap['scans']:
        t = s['targets']
        rows.append(
            {
                'id': s['id'],
                'name': s['name'],
                'kind': scan_kind(s),
                'template': s.get('template'),
                'enabled': bool(s['schedule'].get('enabled')),
                'schedule': schedule_text(s),
                'scanner': (s['scanner'] or {}).get('name'),
                'network': (s['network'] or {}).get('name'),
                'text_targets': len(t['text']),
                'target_groups': [name_of(inv['target_groups'], g) for g in t['target_groups']],
                'tags': [tag_label(snap, u) for u in t['tags']],
                'agent_groups': [name_of(inv['agent_groups'], g) for g in t['agent_groups']],
                'addresses': address_count(s['_resolved']['intervals']),
                'credentials': len(s['credentials']),
                'owner': s.get('owner'),
            }
        )
    emit(args.format, rows, header(snap) + md_table(rows, LIST_COLUMNS), rows, LIST_COLUMNS)


def cmd_status(args: argparse.Namespace) -> None:
    snap = load_snapshot(args.snapshot)
    kinds: dict[str, int] = {}
    for s in snap['scans']:
        kinds[scan_kind(s)] = kinds.get(scan_kind(s), 0) + 1
    info = {
        'snapshot': snap['_path'],
        'platform': snap.get('platform', 'vm'),
        'container': snap['container'],
        'collected_at': snap['collected_at'],
        'age_hours': round(snapshot_age_hours(snap), 1),
        'stale': snapshot_age_hours(snap) > STALE_HOURS,
        'scans': len(snap['scans']),
        'by_kind': kinds,
        'listing': {k: v for k, v in snap.get('listing', {}).items() if k != 'folders'},
        'exclusions': len(snap.get('exclusions', [])),
        'errors': len(snap.get('errors', [])),
        'inventory': {k: len(v) for k, v in snap['inventory'].items()},
    }
    md = '\n'.join(f'- **{k}:** {v}' for k, v in info.items()) + '\n'
    emit(args.format, info, md)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='scan_sweep.py', description=__doc__.split('\n\n')[0])
    parser.add_argument('--version', action='version', version=VERSION)
    sub = parser.add_subparsers(dest='command', required=True)

    def common(p: argparse.ArgumentParser, formats: tuple[str, ...] = ('md', 'json', 'csv')) -> None:
        p.add_argument('--snapshot', help='Snapshot file (default: the newest in $SCAN_SWEEP_HOME, else ~/.cache/tenable-scan-sweep).')
        p.add_argument('--format', choices=formats, default='md')

    p = sub.add_parser('collect', help='Read every scan configuration (read-only) into a local snapshot.')
    p.add_argument('--platform', choices=('vm', 'sc'), default='vm', help='vm = Tenable Vulnerability Management (default); sc = Tenable Security Center.')
    p.add_argument('--url', help=f'Platform URL (default: $TIO_URL or {DEFAULT_URL} for vm; $TSC_URL for sc, which is required).')
    p.add_argument('--env-prefix', help='Prefix of the API key variables (default: TIO for vm, TSC for sc).')
    p.add_argument('--workers', type=int, default=4, help='Concurrent editor requests (default: 4; vm only).')
    p.add_argument('--ca-bundle', help='CA bundle for verifying the Security Center certificate (sc only).')
    p.add_argument('--insecure', action='store_true', help='Skip TLS certificate verification (sc only; not recommended).')
    p.add_argument('--snapshot', help='Where to write the snapshot.')
    p.add_argument('--assets', action='store_true', help='vm: also index assets and agents (one asset export plus the agent list), so find resolves tag and agent scans. sc: also read the current members of rule-based asset lists that scans use.')
    p.add_argument('--include-credential-summaries', action='store_true', help='Also keep summaries of scan-specific (ad hoc) credentials, which can include usernames.')
    p.set_defaults(func=collect)

    p = sub.add_parser('find', help='Which scans target these IPs, ranges, hostnames or selectors?')
    p.add_argument('targets', nargs='+', help='IP, CIDR, range, hostname, or selector such as tag:Category:Value, agent-group:Name, scanner:Name, credential:SSH.')
    p.add_argument('--asset-tag', action='append', metavar='CATEGORY:VALUE', help='A tag the asset has; also matches scans that target that tag. Repeatable.')
    p.add_argument('--asset-list', action='append', metavar='NAME', help='A rule-based Security Center asset list the asset belongs to; also matches scans that use it. Repeatable.')
    common(p)
    p.set_defaults(func=cmd_find)

    p = sub.add_parser('overlaps', help='Pairs of network scans that scan the same addresses.')
    p.add_argument('--include-disabled', action='store_true', help='Include scans with no enabled schedule.')
    p.add_argument('--min-shared', type=int, default=1, help='Minimum shared addresses (default: 1).')
    p.add_argument('--limit', type=int, default=50, help='Rows to show in markdown output (default: 50).')
    common(p)
    p.set_defaults(func=cmd_overlaps)

    p = sub.add_parser('audit', help='Scan hygiene findings: missing targets or credentials, duplicates, unused groups.')
    common(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser('credentials', help='Credential usage across scans, and credentialed templates without credentials.')
    common(p)
    p.set_defaults(func=cmd_credentials)

    p = sub.add_parser('show', help='One scan\'s normalized configuration.')
    p.add_argument('scan', help='Scan ID or (part of) its name.')
    common(p, ('md', 'json'))
    p.set_defaults(func=cmd_show)

    p = sub.add_parser('list', help='Every scan, one row each.')
    common(p)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser('status', help='Snapshot age and counts.')
    common(p, ('md', 'json'))
    p.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> None:
    # Scan names can hold any Unicode; don't let a Windows console or a redirected
    # cp1252 stdout crash the report.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main()
