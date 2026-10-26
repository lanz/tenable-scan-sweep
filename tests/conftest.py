import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import scan_sweep  # noqa: E402

AG_WEB = '11111111-1111-1111-1111-111111111111'
AG_DB = '22222222-2222-2222-2222-222222222222'
TAG_AUSTIN = '33333333-3333-3333-3333-333333333333'
TAG_PROD = '44444444-4444-4444-4444-444444444444'
SCANNER_A = '55555555-5555-5555-5555-555555555555'
SCANNER_B = '66666666-6666-6666-6666-666666666666'
CRED_ID = '77777777-7777-7777-7777-777777777777'


def editor(
    title='Basic Network Scan',
    text_targets='',
    asset_lists=None,
    tag_targets=None,
    agent_groups=None,
    scanner=SCANNER_A,
    enabled=True,
    rrules='FREQ=WEEKLY;INTERVAL=1;BYDAY=MO',
    credentials=None,
    policy_id=None,
):
    """A trimmed GET /editor/scan/{id} response with the fields the sweep reads."""
    inputs = [
        {'id': 'text_targets', 'type': 'textarea', 'default': text_targets},
        {'id': 'file_targets', 'type': 'file', 'default': None},
        {
            'id': 'asset_lists',
            'type': 'multi_select',
            'default': asset_lists or [],
            'options': [{'id': 9, 'name': 'Legacy DMZ', 'members': '198.51.100.0/28, legacy.example.com', 'type': 'user'}],
        },
        {
            'id': 'tag_targets',
            'type': 'multi_select',
            'default': tag_targets or [],
            'options': [
                {'uuid': TAG_AUSTIN, 'category_name': 'Location', 'value': 'Austin', 'category_uuid': 'c1'},
                {'uuid': TAG_PROD, 'category_name': 'Env', 'value': 'Prod', 'category_uuid': 'c2'},
            ],
        },
        {'id': 'use_tag_rules_as_targets', 'type': 'select', 'default': 0, 'options': [{'name': 'Existing tagged assets only', 'value': 0}, {'name': 'Targets defined by tags', 'value': 1}]},
        {
            'id': 'agent_group_id',
            'type': 'multi_select',
            'default': agent_groups or [],
            'options': [{'id': AG_WEB, 'name': 'Web servers'}, {'id': AG_DB, 'name': 'Databases'}],
        },
        {
            'id': 'scanner_id',
            'type': 'select',
            'default': scanner,
            'options': [
                {'id': SCANNER_A, 'name': 'Austin scanner', 'type': 'local', 'status': 'on', 'value': 'a', 'linked': 1, 'network_name': 'Default'},
                {'id': SCANNER_B, 'name': 'Spare scanner', 'type': 'local', 'status': 'on', 'value': 'b', 'linked': 1, 'network_name': 'Default'},
            ],
        },
    ]
    if policy_id:
        inputs.append({'id': 'policy_id', 'type': 'select', 'default': policy_id, 'options': [{'id': policy_id, 'name': 'Hardened Linux', 'owner_id': 1, 'targets': None, 'template_uuid': 't'}]})
    data = []
    if credentials:
        data = [{'name': 'Host', 'default_expand': True, 'types': [{'name': name, 'max': 10, 'settings': None, 'inputs': [], 'instances': [inst]} for name, inst in credentials]}]
    return {
        'title': title,
        'name': 'ignored',
        'uuid': 'template-uuid',
        'settings': {
            'basic': {
                'groups': [
                    {'name': 'schedule', 'enabled': enabled, 'rrules': rrules, 'starttime': '20260101T020000', 'timezone': 'UTC', 'inputs': inputs}
                ]
            }
        },
        'credentials': {'data': data},
    }


SCANS = [
    ({'id': 1, 'name': 'Weekly DMZ', 'type': 'remote', 'enabled': True, 'owner': 'a@example.com'}, editor(text_targets='192.0.2.0/24, web01.example.com, bad target!!')),
    ({'id': 2, 'name': 'DMZ copy', 'type': 'remote', 'enabled': True}, editor(text_targets='192.0.2.0-192.0.2.255', scanner=SCANNER_A)),
    ({'id': 3, 'name': 'Austin by tag', 'type': 'remote', 'enabled': True}, editor(tag_targets=[TAG_AUSTIN])),
    ({'id': 4, 'name': 'Web agents', 'type': 'agent', 'enabled': True}, editor(title='Basic Agent Scan', agent_groups=[AG_WEB])),
    ({'id': 5, 'name': 'Legacy', 'type': 'remote', 'enabled': False}, editor(asset_lists=[9], enabled=False, rrules=None)),
    (
        {'id': 6, 'name': 'Credentialed core', 'type': 'remote', 'enabled': True},
        editor(text_targets='10.0.0.0/16', credentials=[('SSH', {'id': CRED_ID, 'ad_hoc': False, 'summary': 'Linux service account', 'inputs': []}), ('Windows', {'id': 1, 'ad_hoc': True, 'summary': 'admin@corp', 'inputs': []})]),
    ),
    ({'id': 7, 'name': 'Empty', 'type': 'remote', 'enabled': True}, editor()),
    ({'id': 8, 'name': 'From policy', 'type': 'remote', 'enabled': True}, editor(title='Custom Scan', text_targets='203.0.113.0/28', policy_id=42)),
]


@pytest.fixture
def snapshot(tmp_path):
    inventory = {k: {} for k in ('agent_groups', 'tags', 'target_groups', 'scanners', 'networks', 'policies')}
    records = [scan_sweep.normalize_scan(summary, ed, inventory, False) for summary, ed in SCANS]
    snap = {
        'tool': 'tenable-scan-sweep',
        'version': scan_sweep.VERSION,
        'collected_at': '2099-01-01T00:00:00+00:00',
        'container': 'example.invalid',
        'listing': {'paginated': False, 'listed': len(records)},
        'scans': records,
        'inventory': inventory,
        'exclusions': [{'id': 1, 'name': 'Maintenance window', 'members': ['192.0.2.10'], 'schedule_enabled': True, 'rrules': None, 'network_id': None}],
        'errors': [],
    }
    path = tmp_path / 'snap.json'
    import json

    path.write_text(json.dumps(snap), encoding='utf-8')
    return scan_sweep.load_snapshot(str(path))
