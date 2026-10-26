import argparse
import json
import re

import responses
from responses import matchers

import scan_sweep
from conftest import SCANS

BASE = 'https://cloud.example.invalid'


def _args(tmp_path):
    return argparse.Namespace(
        env_prefix='TIO', url=BASE, workers=2, snapshot=str(tmp_path / 'snap.json'), include_credential_summaries=False
    )


@responses.activate
def test_collect_pages_through_paginated_scan_list(tmp_path, monkeypatch):
    monkeypatch.setenv('TIO_ACCESS_KEY', 'a' * 64)
    monkeypatch.setenv('TIO_SECRET_KEY', 'b' * 64)
    monkeypatch.setattr(scan_sweep, 'PAGE_SIZE', 4)
    summaries = [summary for summary, _ in SCANS]
    responses.get(
        f'{BASE}/scans',
        match=[matchers.query_param_matcher({'limit': '4', 'offset': '0'})],
        json={'scans': summaries[:4], 'folders': [], 'pagination': {'total': len(summaries), 'limit': 4, 'offset': 0}},
    )
    responses.get(
        f'{BASE}/scans',
        match=[matchers.query_param_matcher({'limit': '4', 'offset': '4'})],
        json={'scans': summaries[4:], 'folders': [], 'pagination': {'total': len(summaries), 'limit': 4, 'offset': 4}},
    )
    by_id = {summary['id']: ed for summary, ed in SCANS}
    responses.add_callback(
        responses.GET,
        re.compile(rf'{BASE}/editor/scan/\d+'),
        callback=lambda req: (200, {'Content-Type': 'application/json'}, json.dumps(by_id[int(req.url.rsplit('/', 1)[1])])),
    )
    policy_editor = {'credentials': {'data': [{'name': 'Host', 'types': [{'name': 'SSH', 'instances': [{'id': 5, 'ad_hoc': True, 'summary': 'root', 'inputs': []}]}]}]}}
    responses.get(f'{BASE}/editor/policy/42', json=policy_editor)
    responses.get(f'{BASE}/exclusions', json={'exclusions': [{'id': 1, 'name': 'Window', 'members': '10.0.0.1', 'schedule': {'enabled': False}}]})

    scan_sweep.collect(_args(tmp_path))

    snap = json.loads((tmp_path / 'snap.json').read_text())
    assert snap['listing'] == {'paginated': True, 'reported_total': 8, 'listed': 8, 'trashed_skipped': 0, 'folders': {}}
    assert len(snap['scans']) == 8
    from_policy = next(s for s in snap['scans'] if s['name'] == 'From policy')
    assert from_policy['credentials'] == [{'category': 'Host', 'type': 'SSH', 'managed': False, 'source': 'policy'}]
    assert snap['exclusions'][0]['members'] == ['10.0.0.1']
    # Read-only: every request the tool made was a GET.
    assert {call.request.method for call in responses.calls} == {'GET'}
    # The ad hoc credential's summary (which can hold a username) isn't stored.
    assert 'admin@corp' not in json.dumps(snap)


@responses.activate
def test_collect_unpaginated_list_and_per_scan_errors(tmp_path, monkeypatch):
    monkeypatch.setenv('TIO_ACCESS_KEY', 'a' * 64)
    monkeypatch.setenv('TIO_SECRET_KEY', 'b' * 64)
    summaries = [summary for summary, _ in SCANS[:2]]
    responses.get(f'{BASE}/scans', json={'scans': summaries, 'folders': []})
    responses.get(f'{BASE}/editor/scan/1', json=SCANS[0][1])
    responses.get(f'{BASE}/editor/scan/2', status=404, json={'error': 'not found'})
    responses.get(f'{BASE}/exclusions', json={'exclusions': []})

    scan_sweep.collect(_args(tmp_path))

    snap = json.loads((tmp_path / 'snap.json').read_text())
    assert snap['listing']['paginated'] is False
    assert [s['id'] for s in snap['scans']] == [1]
    assert snap['errors'][0]['scan_id'] == 2


def test_missing_keys_exit(monkeypatch, tmp_path):
    monkeypatch.delenv('TIO_ACCESS_KEY', raising=False)
    monkeypatch.delenv('TIO_SECRET_KEY', raising=False)
    try:
        scan_sweep.collect(_args(tmp_path))
    except SystemExit as exc:
        assert 'TIO_ACCESS_KEY' in str(exc)
    else:  # pragma: no cover
        raise AssertionError('expected SystemExit')


@responses.activate
def test_collect_skips_trash_and_pages_exclusions(tmp_path, monkeypatch):
    monkeypatch.setenv('TIO_ACCESS_KEY', 'a' * 64)
    monkeypatch.setenv('TIO_SECRET_KEY', 'b' * 64)
    monkeypatch.setattr(scan_sweep, 'PAGE_SIZE', 1)
    folders = [{'id': 10, 'type': 'main', 'name': 'My Scans'}, {'id': 11, 'type': 'trash', 'name': 'Trash'}]
    s1, s2 = SCANS[0][0], SCANS[1][0]
    responses.get(f'{BASE}/scans', match=[matchers.query_param_matcher({'limit': '1', 'offset': '0'})], json={'scans': [s1, s2], 'folders': folders})
    responses.get(f'{BASE}/scans', match=[matchers.query_param_matcher({'folder_id': '11', 'limit': '1', 'offset': '0'})], json={'scans': [s2], 'folders': folders})
    responses.get(f'{BASE}/editor/scan/1', json=SCANS[0][1])
    responses.get(f'{BASE}/editor/scan/2', json=SCANS[1][1])
    ex = lambda i: {'id': i, 'name': f'Window {i}', 'members': f'10.0.0.{i}', 'schedule': {'enabled': True}}  # noqa: E731
    responses.get(f'{BASE}/exclusions', match=[matchers.query_param_matcher({'limit': '1', 'offset': '0'})], json={'exclusions': [ex(1)], 'pagination': {'total': 2, 'limit': 1, 'offset': 0}})
    responses.get(f'{BASE}/exclusions', match=[matchers.query_param_matcher({'limit': '1', 'offset': '1'})], json={'exclusions': [ex(2)], 'pagination': {'total': 2, 'limit': 1, 'offset': 1}})

    scan_sweep.collect(_args(tmp_path))

    snap = json.loads((tmp_path / 'snap.json').read_text())
    assert [s['id'] for s in snap['scans']] == [1]
    assert snap['listing']['trashed_skipped'] == 1
    assert [e['name'] for e in snap['exclusions']] == ['Window 1', 'Window 2']


@responses.activate
def test_rejected_keys_give_a_clear_error(monkeypatch, tmp_path):
    monkeypatch.setenv('TIO_ACCESS_KEY', 'a' * 64)
    monkeypatch.setenv('TIO_SECRET_KEY', 'b' * 64)
    responses.get(f'{BASE}/scans', status=401, json={'error': 'Invalid Credentials'})
    try:
        scan_sweep.collect(_args(tmp_path))
    except SystemExit as exc:
        assert '401' in str(exc) and 'TIO_ACCESS_KEY' in str(exc)
    else:  # pragma: no cover
        raise AssertionError('expected SystemExit')
