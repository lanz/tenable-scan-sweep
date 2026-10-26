import json

import scan_sweep
from conftest import CRED_ID


def names(result):
    return sorted(m['name'] for m in result['matches'])


def test_find_ip_matches_cidr_range_and_reports_exclusion(snapshot):
    result = scan_sweep.find_matches(snapshot, '192.0.2.10', [])
    assert names(result) == ['DMZ copy', 'Weekly DMZ']
    assert result['excluded_by'] == [{'name': 'Maintenance window', 'schedule_enabled': True, 'network': None}]
    # The tag-targeted scan can't be ruled in or out without the asset's tags.
    assert result['unresolved_tag_scans'] == 1
    assert result['unresolved_tags'] == ['Location:Austin']
    assert result['agent_scans_not_checked'] == 1


def test_find_ip_with_asset_tag_resolves_tag_scans(snapshot):
    result = scan_sweep.find_matches(snapshot, '192.0.2.10', ['location:austin'])
    assert 'Austin by tag' in names(result)
    assert result['unresolved_tag_scans'] == 0


def test_find_cidr_reports_shared_addresses(snapshot):
    result = scan_sweep.find_matches(snapshot, '192.0.2.128/25', [])
    row = next(m for m in result['matches'] if m['name'] == 'Weekly DMZ')
    assert row['matched_by'] == ['target 192.0.2.0/24 (128 shared addresses)']


def test_find_ip_through_target_group(snapshot):
    result = scan_sweep.find_matches(snapshot, '198.51.100.5', [])
    assert names(result) == ['Legacy']
    assert result['matches'][0]['matched_by'] == ["target group 'Legacy DMZ' 198.51.100.0/28"]


def test_find_hostname_exact_and_short_name(snapshot):
    assert names(scan_sweep.find_matches(snapshot, 'WEB01.example.com', [])) == ['Weekly DMZ']
    short = scan_sweep.find_matches(snapshot, 'web01', [])
    assert short['matches'][0]['matched_by'] == ['target web01.example.com (possible: same short name)']


def test_selectors(snapshot):
    assert names(scan_sweep.find_matches(snapshot, 'tag:Location:Austin', [])) == ['Austin by tag']
    assert names(scan_sweep.find_matches(snapshot, 'agent-group:web', [])) == ['Web agents']
    assert names(scan_sweep.find_matches(snapshot, 'target-group:legacy', [])) == ['Legacy']
    assert names(scan_sweep.find_matches(snapshot, 'credential:ssh', [])) == ['Credentialed core']
    assert len(scan_sweep.find_matches(snapshot, 'scanner:austin', [])['matches']) == 8


def test_unknown_query(snapshot):
    assert scan_sweep.find_matches(snapshot, '!!!', [])['error']


def test_overlaps_flags_identical_targets(snapshot):
    pairs = scan_sweep.find_overlaps(snapshot, include_disabled=False, min_shared=1)
    assert pairs[0]['identical'] is True
    assert {pairs[0]['scan_a'], pairs[0]['scan_b']} == {'Weekly DMZ', 'DMZ copy'}
    assert pairs[0]['shared_addresses'] == 256


def test_audit_findings(snapshot):
    checks = {(f['check'], f['scan']) for f in scan_sweep.audit(snapshot)}
    assert ('no-targets', 'Empty') in checks
    assert ('unparsed-targets', 'Weekly DMZ') in checks
    assert ('uncredentialed', 'Weekly DMZ') in checks
    assert ('uncredentialed', 'Credentialed core') not in checks
    assert ('on-demand', 'Legacy') in checks
    assert ('target-groups', 'Legacy') in checks
    assert ('duplicate-targets', '') in checks
    assert ('unused-agent-group', '') in checks
    assert ('unused-scanner', '') in checks


def test_credentials_hide_ad_hoc_summaries(snapshot):
    scan = next(s for s in snapshot['scans'] if s['name'] == 'Credentialed core')
    managed, ad_hoc = scan['credentials']
    assert managed == {'category': 'Host', 'type': 'SSH', 'managed': True, 'source': 'scan', 'id': CRED_ID, 'summary': 'Linux service account'}
    assert 'summary' not in ad_hoc
    usage = scan_sweep.credential_usage(snapshot)
    assert usage['managed'] == {'Linux service account': ['Credentialed core']}
    assert 'Weekly DMZ' in {s['name'] for s in usage['uncredentialed_scans']}


def test_schedule_text(snapshot):
    by_name = {s['name']: s for s in snapshot['scans']}
    assert scan_sweep.schedule_text(by_name['Weekly DMZ']) == 'weekly (MO)'
    assert scan_sweep.schedule_text(by_name['Legacy']) == 'on demand'


def test_cli_find_json(snapshot, capsys):
    scan_sweep.main(['find', '192.0.2.10', '--snapshot', snapshot['_path'], '--format', 'json'])
    out = json.loads(capsys.readouterr().out)
    assert out[0]['query'] == '192.0.2.10'


def test_cli_markdown_commands_run(snapshot, capsys):
    for cmd in (['overlaps'], ['audit'], ['credentials'], ['list', '--format', 'csv'], ['show', 'Legacy'], ['status']):
        scan_sweep.main([*cmd, '--snapshot', snapshot['_path']])
    assert 'Weekly DMZ' in capsys.readouterr().out


def test_find_reports_scans_it_could_not_check(snapshot):
    result = scan_sweep.find_matches(snapshot, '203.0.113.200', [])
    # 'Weekly DMZ' has a hostname target and an unparsed target; neither can be ruled out offline.
    assert result['unchecked_scans']['unparsed targets'] == 1
    assert result['unchecked_scans']['hostname targets (IP query not resolved to names)'] >= 1


def test_overlaps_only_within_a_network(snapshot):
    other = next(s for s in snapshot['scans'] if s['name'] == 'DMZ copy')
    other['network'] = {'uuid': 'aaaaaaaa-0000-0000-0000-000000000000', 'name': 'Branch'}
    pairs = scan_sweep.find_overlaps(snapshot, include_disabled=False, min_shared=1)
    assert not any({p['scan_a'], p['scan_b']} == {'Weekly DMZ', 'DMZ copy'} for p in pairs)


def test_approximate_octet_match_is_labelled(snapshot):
    scan = next(s for s in snapshot['scans'] if s['name'] == 'Empty')
    scan['targets']['text'] = ['10.0-255.0-255.1-254']
    scan['_resolved'] = scan_sweep.resolve_scan_targets(scan, snapshot)
    row = next(m for m in scan_sweep.find_matches(snapshot, '10.5.5.0', [])['matches'] if m['name'] == 'Empty')
    assert 'approximate' in row['matched_by'][0]


def test_csv_neutralizes_formulas():
    out = scan_sweep.csv_text([{'name': '=HYPERLINK("x")'}, {'name': 'plain'}], ['name'])
    assert "'=HYPERLINK" in out and '\nplain' in out


def test_rejects_non_snapshot_json(tmp_path):
    bad = tmp_path / 'other.json'
    bad.write_text('{"hello": 1}', encoding='utf-8')
    try:
        scan_sweep.load_snapshot(str(bad))
    except SystemExit as exc:
        assert 'not a tenable-scan-sweep snapshot' in str(exc)
    else:  # pragma: no cover
        raise AssertionError('expected SystemExit')


def test_hostname_in_another_domain_does_not_match(snapshot):
    assert names(scan_sweep.find_matches(snapshot, 'web01.other.example', [])) == []
    assert scan_sweep.host_match('web01.example.com', 'web01') == 'possible'
    assert scan_sweep.host_match('web01.example.com', 'web01.other.example') is None


def test_no_targets_severity_follows_the_schedule(snapshot):
    empty = next(f for f in scan_sweep.audit(snapshot) if f['check'] == 'no-targets' and f['scan'] == 'Empty')
    assert empty['severity'] == 'warn'  # scheduled, so it runs and scans nothing


def test_find_says_when_exclusions_were_not_collected(snapshot, capsys):
    snapshot['errors'] = [{'scan_id': None, 'name': 'exclusions', 'error': 'ForbiddenError'}]
    result = scan_sweep.find_matches(snapshot, '192.0.2.10', [])
    assert result['exclusions_collected'] is False


def test_show_falls_back_to_names_that_are_numbers(snapshot):
    snapshot['scans'][0]['name'] = '2024'
    assert [s['name'] for s in scan_sweep.find_scan(snapshot, '2024')] == ['2024']
    assert [s['id'] for s in scan_sweep.find_scan(snapshot, '2')] == [2]


def test_snapshot_name_includes_a_custom_prefix(monkeypatch, tmp_path):
    monkeypatch.setenv('SCAN_SWEEP_HOME', str(tmp_path))
    assert scan_sweep.default_snapshot_path('cloud.tenable.com', 'TIO').name == 'cloud.tenable.com.json'
    assert scan_sweep.default_snapshot_path('cloud.tenable.com', 'PROD').name == 'cloud.tenable.com-prod.json'


def test_auto_selection_skips_other_json(monkeypatch, tmp_path, snapshot):
    monkeypatch.setenv('SCAN_SWEEP_HOME', str(tmp_path / 'home'))
    (tmp_path / 'home').mkdir()
    (tmp_path / 'home' / 'good.json').write_text(open(snapshot['_path'], encoding='utf-8').read(), encoding='utf-8')
    (tmp_path / 'home' / 'zz-notes.json').write_text('{"other": true}', encoding='utf-8')
    assert scan_sweep.load_snapshot(None)['_path'].endswith('good.json')
