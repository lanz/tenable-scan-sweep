"""The optional asset index: resolving tag-targeted and agent scans for a specific asset."""

import argparse
import json
import re

import pytest
import responses

import scan_sweep
from conftest import SCANS

BASE = 'https://cloud.example.invalid'

INDEX = {
    'collected_at': '2099-01-01T00:00:00+00:00',
    'assets': [
        {'id': 'a1', 'ipv4s': ['192.0.2.10'], 'ipv6s': [], 'names': ['web01.example.com'], 'tags': ['Location:Austin'], 'agent_uuid': 'abc123'},
        {'id': 'a2', 'ipv4s': ['203.0.113.50'], 'ipv6s': [], 'names': ['db01.example.com'], 'tags': ['Env:Prod'], 'agent_uuid': None},
    ],
    'agents': [{'uuid': 'abc123', 'name': 'web01', 'ip': '192.0.2.10', 'groups': ['web servers']}],
}


@pytest.fixture
def indexed(snapshot):
    snapshot['asset_index'] = INDEX
    return snapshot


def names(result):
    return sorted(m['name'] for m in result['matches'])


def test_index_resolves_tags_and_agent_groups(indexed):
    result = scan_sweep.find_matches(indexed, '192.0.2.10', [])
    assert 'Austin by tag' in names(result) and 'Web agents' in names(result)
    by_name = {m['name']: m for m in result['matches']}
    assert by_name['Austin by tag']['matched_by'] == ['tag Location:Austin (from asset index)']
    assert by_name['Web agents']['matched_by'] == ["agent group 'Web servers' (from asset index)"]
    assert result['unresolved_tag_scans'] == 0
    assert result['agent_scans_not_checked'] == 0
    assert result['asset_index']['tags'] == ['Location:Austin']


def test_index_by_hostname(indexed):
    result = scan_sweep.find_matches(indexed, 'WEB01.example.com', [])
    assert 'Austin by tag' in names(result)


def test_index_rules_out_tags_the_asset_lacks(indexed):
    # db01 carries Env:Prod only, so the Location:Austin scan is not a match, and no longer "unresolved".
    result = scan_sweep.find_matches(indexed, '203.0.113.50', [])
    assert 'Austin by tag' not in names(result)
    assert result['unresolved_tag_scans'] == 0


def test_address_missing_from_index_stays_unresolved(indexed):
    result = scan_sweep.find_matches(indexed, '198.51.100.99', [])
    assert result['asset_index']['assets_matched'] == 0
    assert result['unresolved_tag_scans'] == 1
    assert result['agent_scans_not_checked'] == 1


def test_markdown_reports_index_use(indexed, capsys):
    path = indexed['_path']
    data = json.loads(open(path, encoding='utf-8').read())
    data['asset_index'] = INDEX
    open(path, 'w', encoding='utf-8').write(json.dumps(data))
    scan_sweep.main(['find', '192.0.2.10', '198.51.100.99', '--snapshot', path])
    out = capsys.readouterr().out
    assert 'Resolved from the asset index' in out and 'Not found in the asset index' in out


@responses.activate
def test_collect_with_assets_builds_index(tmp_path, monkeypatch):
    monkeypatch.setenv('TIO_ACCESS_KEY', 'a' * 64)
    monkeypatch.setenv('TIO_SECRET_KEY', 'b' * 64)
    summary, editor = SCANS[0]
    responses.get(f'{BASE}/scans', json={'scans': [summary], 'folders': []})
    responses.get(f'{BASE}/editor/scan/1', json=editor)
    responses.get(f'{BASE}/exclusions', json={'exclusions': []})
    uuid = '11111111-2222-3333-4444-555555555555'
    responses.post(f'{BASE}/assets/export', json={'export_uuid': uuid})
    responses.get(f'{BASE}/assets/export/{uuid}/status', json={'status': 'FINISHED', 'chunks_available': [1]})
    responses.get(f'{BASE}/assets/export/{uuid}/chunks/1', json=[
        {'id': 'a1', 'ipv4s': ['192.0.2.10'], 'fqdns': ['Web01.example.com.'], 'hostnames': ['web01'], 'netbios_names': [],
         'tags': [{'key': 'Location', 'value': 'Austin', 'uuid': 'x'}], 'agent_uuid': 'ABC-123'},
    ])
    responses.get(re.compile(rf'{BASE}/scanners/null/agents.*'), json={
        'agents': [{'uuid': 'abc-123', 'name': 'WEB01', 'ip': '192.0.2.10', 'groups': [{'id': 7, 'name': 'Web servers'}]}],
        'pagination': {'total': 1, 'offset': 0, 'limit': 200},
    })
    ns = argparse.Namespace(platform='vm', env_prefix='TIO', url=BASE, workers=1, snapshot=str(tmp_path / 's.json'),
                            include_credential_summaries=False, assets=True)
    scan_sweep.collect(ns)
    snap = json.loads((tmp_path / 's.json').read_text())
    idx = snap['asset_index']
    assert idx['assets'] == [{'id': 'a1', 'ipv4s': ['192.0.2.10'], 'ipv6s': [], 'names': ['web01', 'web01.example.com'],
                              'tags': ['Location:Austin'], 'agent_uuid': 'abc123'}]
    assert idx['agents'] == [{'uuid': 'abc123', 'name': 'web01', 'ip': '192.0.2.10', 'groups': ['web servers']}]
    # The only non-GET request is the asset export itself.
    assert {(c.request.method, c.request.url.split('?')[0].replace(BASE, '')) for c in responses.calls if c.request.method != 'GET'} == {('POST', '/assets/export')}


@responses.activate
def test_agent_list_failure_keeps_the_assets(tmp_path, monkeypatch):
    monkeypatch.setenv('TIO_ACCESS_KEY', 'a' * 64)
    monkeypatch.setenv('TIO_SECRET_KEY', 'b' * 64)
    summary, editor = SCANS[0]
    responses.get(f'{BASE}/scans', json={'scans': [summary], 'folders': []})
    responses.get(f'{BASE}/editor/scan/1', json=editor)
    responses.get(f'{BASE}/exclusions', json={'exclusions': []})
    uuid = '11111111-2222-3333-4444-555555555555'
    responses.post(f'{BASE}/assets/export', json={'export_uuid': uuid})
    responses.get(f'{BASE}/assets/export/{uuid}/status', json={'status': 'FINISHED', 'chunks_available': [1]})
    responses.get(f'{BASE}/assets/export/{uuid}/chunks/1', json=[{'id': 'a1', 'ipv4s': ['192.0.2.10'], 'tags': []}])
    responses.get(re.compile(rf'{BASE}/scanners/null/agents.*'), status=403, json={'error': 'Forbidden'})
    ns = argparse.Namespace(platform='vm', env_prefix='TIO', url=BASE, workers=1, snapshot=str(tmp_path / 's.json'),
                            include_credential_summaries=False, assets=True)
    scan_sweep.collect(ns)
    snap = json.loads((tmp_path / 's.json').read_text())
    assert [a['id'] for a in snap['asset_index']['assets']] == ['a1']
    assert snap['asset_index']['agents'] == []
    assert [e['name'] for e in snap['errors']] == ['agent list']
