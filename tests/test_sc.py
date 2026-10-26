"""Security Center collection and queries, against synthetic responses shaped like the SC API."""

import argparse
import json

import pytest
import responses
from responses import matchers

import scan_sweep

SC = 'https://sc.example.invalid'


def envelope(body):
    return {'type': 'regular', 'response': body, 'error_code': 0, 'error_msg': '', 'warnings': [], 'timestamp': 1}


ASSET_LISTS = [
    {'id': '10', 'name': 'DMZ static', 'type': 'static', 'typeFields': {'definedIPs': '192.0.2.0/28,192.0.2.100'}},
    # The list endpoint can omit typeFields; the collector reads this one's detail record.
    {'id': '12', 'name': 'Web names', 'type': 'dnsname'},
    {'id': '14', 'name': 'Linux servers', 'type': 'dynamic', 'typeFields': {'rules': {'operator': 'all', 'children': []}}},
    {'id': '16', 'name': 'Outside watch', 'type': 'watchlist', 'typeFields': {'definedIPs': '203.0.113.200'}},
]

SCANS = [
    {
        'id': '1', 'uuid': 'u1', 'name': 'Weekly DMZ', 'type': 'policy', 'status': '0',
        'ipList': '198.51.100.0/24', 'assets': [{'id': '10', 'name': 'DMZ static'}],
        'repository': {'id': '1', 'name': 'Default'}, 'zone': {'id': '3', 'name': 'Austin zone'},
        'policy': {'id': '100', 'name': 'Internal policy'},
        'credentials': [{'id': '5', 'name': 'Linux service account', 'type': 'ssh'}],
        'schedule': {'id': '9', 'type': 'ical', 'start': 'TZID=UTC:20260101T020000', 'repeatRule': 'FREQ=WEEKLY;INTERVAL=1;BYDAY=MO', 'enabled': 'true'},
        'owner': {'id': '2', 'username': 'alice'},
    },
    {
        'id': '2', 'uuid': 'u2', 'name': 'Linux by rule', 'type': 'policy', 'status': '0', 'ipList': '',
        'assets': [{'id': '14', 'name': 'Linux servers'}, {'id': '12', 'name': 'Web names'}],
        'repository': {'id': '1', 'name': 'Default'}, 'zone': {'id': '0', 'name': ''},
        'policy': {'id': '100', 'name': 'Internal policy'}, 'credentials': [],
        'schedule': {'id': '10', 'type': 'template', 'start': '', 'repeatRule': '', 'enabled': 'true'},
        'owner': {'id': '2', 'username': 'bob'},
    },
    {
        'id': '3', 'uuid': 'u3', 'name': 'Patch check', 'type': 'plugin', 'status': '0', 'ipList': '198.51.100.0/24',
        'plugin': {'id': '19506', 'name': 'Nessus Scan Information'}, 'assets': [],
        'repository': {'id': '2', 'name': 'Branch office'}, 'zone': {'id': '3', 'name': 'Austin zone'},
        'credentials': [],
        'schedule': {'id': '11', 'type': 'dependent', 'dependent': {'id': '1', 'name': 'Weekly DMZ'}},
        'owner': {'id': '2', 'username': 'alice'},
    },
]


def sc_mocks(freeze_available=True):
    responses.get(f'{SC}/rest/system', json=envelope({'version': '6.4.0'}))
    responses.get(f'{SC}/rest/asset', match=[matchers.query_param_matcher({'fields': 'id,name,type,typeFields'})],
                  json=envelope({'usable': ASSET_LISTS, 'manageable': ASSET_LISTS[:1]}))
    responses.get(f'{SC}/rest/asset/12', json=envelope({'id': '12', 'name': 'Web names', 'type': 'dnsname', 'definedDNSNames': 'web01.example.com,web02.example.com'}))
    responses.get(f'{SC}/rest/policy', json=envelope({'usable': [{'id': '100', 'name': 'Internal policy', 'policyTemplate': {'name': 'Basic Network Scan'}}], 'manageable': []}))
    responses.get(f'{SC}/rest/scan', match=[matchers.query_param_matcher({'fields': scan_sweep.SC_SCAN_FIELDS})],
                  json=envelope({'usable': SCANS, 'manageable': SCANS[:2]}))
    windows = [
        {'id': '1', 'name': 'Change freeze', 'ipList': '198.51.100.7', 'assets': [{'id': '14', 'name': 'Linux servers'}],
         'repository': {'id': -1, 'name': ''}, 'enabled': 'true', 'repeatRule': '', 'allIPs': 'false'},
        {'id': '2', 'name': 'Holiday', 'ipList': '', 'assets': [], 'repository': {'id': '1', 'name': 'Default'}, 'enabled': 'false', 'allIPs': 'true'},
    ]
    if freeze_available:
        responses.get(f'{SC}/rest/freeze', json=envelope(windows))
    else:
        responses.get(f'{SC}/rest/freeze', status=404, json={'error_code': 404, 'error_msg': 'not found'})
        responses.get(f'{SC}/rest/blackout', json=envelope(windows))


def args(tmp_path, **kw):
    base = dict(platform='sc', env_prefix=None, url=SC, snapshot=str(tmp_path / 'sc.json'), ca_bundle=None, insecure=False,
                workers=1, include_credential_summaries=False)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def sc_keys(monkeypatch):
    monkeypatch.setenv('TSC_ACCESS_KEY', 'a' * 32)
    monkeypatch.setenv('TSC_SECRET_KEY', 'b' * 32)


@responses.activate
def test_collect_sc_snapshot(tmp_path, sc_keys):
    sc_mocks()
    scan_sweep.collect(args(tmp_path))
    snap = json.loads((tmp_path / 'sc.json').read_text())
    assert snap['platform'] == 'sc'
    assert [s['id'] for s in snap['scans']] == ['2', '3', '1']  # sorted by name, de-duplicated
    lists = snap['inventory']['target_groups']
    assert lists['10']['members'] == ['192.0.2.0/28', '192.0.2.100'] and not lists['10']['rule_based']
    assert lists['12']['members'] == ['web01.example.com', 'web02.example.com']
    assert lists['14']['rule_based'] and lists['14']['members'] == []
    assert lists['16']['members'] == ['203.0.113.200'] and not lists['16']['rule_based']
    by_id = {s['id']: s for s in snap['scans']}
    # On-demand schedules report enabled=true; only real schedules count as enabled.
    assert by_id['1']['enabled'] and by_id['3']['enabled'] and not by_id['2']['enabled']
    weekly = next(s for s in snap['scans'] if s['id'] == '1')
    assert weekly['template'] == 'Basic Network Scan'
    assert weekly['scanner'] == {'id': '3', 'name': 'Austin zone', 'type': 'zone'}
    assert weekly['network'] == {'uuid': '1', 'name': 'Default'}
    assert weekly['credentials'][0]['summary'] == 'Linux service account'
    patch = next(s for s in snap['scans'] if s['id'] == '3')
    assert patch['template'] == 'Single plugin scan (Nessus Scan Information)'
    freeze = {e['name']: e for e in snap['exclusions']}
    assert freeze['Change freeze']['members'] == ['198.51.100.7']
    assert freeze['Change freeze']['unresolved_lists'] == ['Linux servers']
    assert freeze['Holiday']['all_ips'] is True
    assert {c.request.method for c in responses.calls} == {'GET'}


@responses.activate
def test_collect_sc_falls_back_to_blackout_windows(tmp_path, sc_keys):
    sc_mocks(freeze_available=False)
    scan_sweep.collect(args(tmp_path))
    snap = json.loads((tmp_path / 'sc.json').read_text())
    assert [e['name'] for e in snap['exclusions']] == ['Change freeze', 'Holiday']


def test_sc_requires_url_and_keys(tmp_path, monkeypatch):
    monkeypatch.delenv('TSC_URL', raising=False)
    monkeypatch.setenv('TSC_ACCESS_KEY', 'a' * 32)
    monkeypatch.setenv('TSC_SECRET_KEY', 'b' * 32)
    with pytest.raises(SystemExit, match='TSC_URL'):
        scan_sweep.collect(args(tmp_path, url=None))
    monkeypatch.delenv('TSC_ACCESS_KEY')
    with pytest.raises(SystemExit, match='TSC_ACCESS_KEY'):
        scan_sweep.collect(args(tmp_path))


@responses.activate
def test_tls_verification_is_on_by_default(sc_keys):
    responses.get(f'{SC}/rest/system', json=envelope({'version': '6.4.0'}))
    assert scan_sweep.connect_sc('TSC', SC, True)._ssl_verify is True
    assert scan_sweep.connect_sc('TSC', SC, '/path/ca.pem')._ssl_verify == '/path/ca.pem'


@pytest.fixture
def sc_snapshot(tmp_path, sc_keys):
    responses.start()
    try:
        sc_mocks()
        scan_sweep.collect(args(tmp_path))
    finally:
        responses.stop()
        responses.reset()
    return scan_sweep.load_snapshot(str(tmp_path / 'sc.json'))


def names(result):
    return sorted(m['name'] for m in result['matches'])


def test_find_ip_in_static_asset_list_and_freeze(sc_snapshot):
    result = scan_sweep.find_matches(sc_snapshot, '192.0.2.5', [])
    assert names(result) == ['Weekly DMZ']
    assert result['matches'][0]['matched_by'] == ["asset list 'DMZ static' 192.0.2.0/28"]
    # 'Holiday' covers all IPs but is disabled, so it doesn't apply. 'Change freeze' uses a
    # rule-based list that can't be checked offline, so it's only a possible exclusion.
    assert result['excluded_by'] == []
    assert result['possibly_excluded_by'] == [{'name': 'Change freeze', 'unresolved_lists': ['Linux servers']}]
    assert result['unresolved_list_scans'] == 1 and result['unresolved_lists'] == ['Linux servers']


def test_enabled_freeze_window_excludes(sc_snapshot):
    assert [e['name'] for e in scan_sweep.find_matches(sc_snapshot, '198.51.100.7', [])['excluded_by']] == ['Change freeze']


@responses.activate
def test_unreadable_literal_list_is_unresolved_not_empty(tmp_path, sc_keys):
    sc_mocks()
    responses.replace(responses.GET, f'{SC}/rest/asset/12', status=500, json={'error_code': 500, 'error_msg': 'boom'})
    scan_sweep.collect(args(tmp_path))
    snap = scan_sweep.load_snapshot(str(tmp_path / 'sc.json'))
    assert snap['inventory']['target_groups']['12']['rule_based'] is True
    result = scan_sweep.find_matches(snap, 'web02.example.com', [])
    assert 'Web names' in result['unresolved_lists']


def test_find_with_asset_list_membership(sc_snapshot):
    result = scan_sweep.find_matches(sc_snapshot, '203.0.113.9', [], ['linux servers'])
    assert names(result) == ['Linux by rule']
    assert result['matches'][0]['matched_by'] == ["asset list 'Linux servers' (membership supplied)"]
    assert result['unresolved_list_scans'] == 0


def test_find_hostname_in_dnsname_list(sc_snapshot):
    assert names(scan_sweep.find_matches(sc_snapshot, 'web02.example.com', [])) == ['Linux by rule']


def test_sc_selectors(sc_snapshot):
    assert names(scan_sweep.find_matches(sc_snapshot, 'asset-list:dmz', [])) == ['Weekly DMZ']
    assert names(scan_sweep.find_matches(sc_snapshot, 'repository:branch', [])) == ['Patch check']
    assert names(scan_sweep.find_matches(sc_snapshot, 'zone:austin', [])) == ['Patch check', 'Weekly DMZ']
    assert names(scan_sweep.find_matches(sc_snapshot, 'credential:ssh', [])) == ['Weekly DMZ']


def test_overlaps_respect_repositories(sc_snapshot):
    # Weekly DMZ (Default) and Patch check (Branch office) share 198.51.100.0/24 but different repositories.
    pairs = scan_sweep.find_overlaps(sc_snapshot, include_disabled=True, min_shared=1)
    assert not any({p['scan_a'], p['scan_b']} == {'Weekly DMZ', 'Patch check'} for p in pairs)


def test_sc_schedules(sc_snapshot):
    by_name = {s['name']: s for s in sc_snapshot['scans']}
    assert scan_sweep.schedule_text(by_name['Weekly DMZ']) == 'weekly (MO)'
    assert scan_sweep.schedule_text(by_name['Linux by rule']) == 'on demand'
    assert scan_sweep.schedule_text(by_name['Patch check']) == "after 'Weekly DMZ'"


def test_sc_audit(sc_snapshot):
    checks = {(f['check'], f['scan']) for f in scan_sweep.audit(sc_snapshot)}
    assert ('uncredentialed', 'Linux by rule') in checks
    assert ('uncredentialed', 'Weekly DMZ') not in checks
    assert not any(check == 'target-groups' for check, _ in checks)  # VM-only advice
    assert ('on-demand', 'Linux by rule') in checks
    unused = [f for f in scan_sweep.audit(sc_snapshot) if f['check'].startswith(('unused', 'asset-lists'))]
    assert [(f['check'], f['detail']) for f in unused] == [('asset-lists-not-scan-targets', '1 of 4 asset lists are not used by any scan.')]
    assert ('on-demand', 'Patch check') not in checks  # dependent scans run after their parent


def test_sc_header_names_product(sc_snapshot):
    assert 'Security Center scans' in scan_sweep.header(sc_snapshot)


@responses.activate
def test_sc_assets_resolves_rule_based_lists(tmp_path, sc_keys):
    sc_mocks()
    responses.get(f'{SC}/rest/asset/14', match=[matchers.query_param_matcher({'fields': 'id,name,type,viewableIPs'})], json=envelope({
        'id': '14', 'name': 'Linux servers', 'type': 'dynamic',
        'viewableIPs': [{'repository': {'id': '1', 'name': 'Default'}, 'ipList': '10.20.0.5\n2c5b9f7e-1d2a-4c3b-9e8f-0a1b2c3d4e5f|10.20.0.6\n7d0e1f2a-3b4c-4d5e-8f60-718293a4b5c6|\n', 'ipCount': '3'}],
    }))
    scan_sweep.collect(args(tmp_path, assets=True))
    raw = json.loads((tmp_path / 'sc.json').read_text())
    assert raw['listing']['rule_lists_used'] == 1 and raw['listing']['rule_lists_resolved'] == 1
    listed = raw['inventory']['target_groups']['14']
    assert listed['members'] == ['10.20.0.5', '10.20.0.6'] and listed['resolved'] is True
    # The freeze window that references the list now covers its members.
    freeze = next(e for e in raw['exclusions'] if e['name'] == 'Change freeze')
    assert '10.20.0.6' in freeze['members'] and freeze['unresolved_lists'] == []

    snap = scan_sweep.load_snapshot(str(tmp_path / 'sc.json'))
    hit = scan_sweep.find_matches(snap, '10.20.0.6', [])
    assert names(hit) == ['Linux by rule']
    assert 'rule-based list; members as of' in hit['matches'][0]['matched_by'][0]
    assert hit['unresolved_list_scans'] == 0
    miss = scan_sweep.find_matches(snap, '10.20.0.99', [])
    assert 'Linux by rule' not in names(miss) and miss['unresolved_list_scans'] == 0


@responses.activate
def test_sc_assets_leaves_lists_without_members_unresolved(tmp_path, sc_keys):
    sc_mocks()
    responses.get(f'{SC}/rest/asset/14', json=envelope({'id': '14', 'name': 'Linux servers', 'type': 'dynamic'}))
    scan_sweep.collect(args(tmp_path, assets=True))
    snap = scan_sweep.load_snapshot(str(tmp_path / 'sc.json'))
    assert snap['listing']['rule_lists_resolved'] == 0
    assert scan_sweep.find_matches(snap, '10.20.0.6', [])['unresolved_list_scans'] == 1


@responses.activate
def test_admin_keys_get_a_clear_error(tmp_path, sc_keys):
    sc_mocks()
    responses.replace(responses.GET, f'{SC}/rest/scan', status=403, json={
        'type': 'regular', 'response': '', 'error_code': 163, 'error_msg': 'Administrators may not manage Scans.'})
    with pytest.raises(SystemExit, match='organization user'):
        scan_sweep.collect(args(tmp_path))
