import pytest

from scan_sweep import address_count, merge_intervals, overlap_size, parse_target, split_targets


@pytest.mark.parametrize(
    'raw, kind, count',
    [
        ('192.168.0.1', 'ip', 1),
        ('192.168.0.1:22', 'ip', 1),
        ('2001:db8::2120:17ff:fe56:333b', 'ip', 1),
        ('fe80:0:0:0:216:cbff:fe92:88d0%eth0', 'ip', 1),
        ('192.168.0.1-192.168.0.255', 'range', 255),
        ('192.168.0-1.3-5', 'octets', 6),
        ('192.168.0.1-255', 'octets', 255),
        ('192.168.0.0/24', 'network', 256),
        ('192.168.0.77/24', 'network', 256),
        ('192.168.0.0/255.255.255.128', 'network', 128),
        ('2001:db8::/120', 'network', 256),
        ('Test Host 1[10.0.1.1]', 'ip', 1),
        ('Test Host 2[2001:db8::abcd]', 'ip', 1),
    ],
)
def test_address_formats(raw, kind, count):
    parsed = parse_target(raw)
    assert parsed['kind'] == kind
    assert address_count(merge_intervals(parsed['intervals'])) == count


@pytest.mark.parametrize(
    'raw, kind, hostname',
    [
        ('www.yourdomain.com', 'hostname', 'www.yourdomain.com'),
        ('WEB01', 'hostname', 'web01'),
        ("'link6-lab'", 'hostname', 'link6-lab'),
        ('www.yourdomain.com/24', 'hostname-subnet', 'www.yourdomain.com'),
        ('www.yourdomain.com/255.255.252.0', 'hostname-subnet', 'www.yourdomain.com'),
    ],
)
def test_hostname_formats(raw, kind, hostname):
    parsed = parse_target(raw)
    assert parsed['kind'] == kind
    assert parsed['hostname'] == hostname
    assert parsed['intervals'] == []


@pytest.mark.parametrize('raw', ['link6', 'link6%16'])
def test_link6(raw):
    assert parse_target(raw)['kind'] == 'link6'


@pytest.mark.parametrize(
    'raw',
    [
        '192.168.0.1 - 192.168.0.255',
        '10.0',
        'https://host.example.com',
        '{\\rtf1',
        '300.1.1.1',
        # Malformed addresses must not be mistaken for hostnames.
        '10.0.0.5-3',
        '10.0.0.1-10.0.0',
        '10.0.0.1-',
        '10.0.0/24',
    ],
)
def test_unrecognized_targets(raw):
    assert parse_target(raw)['kind'] == 'unknown'


def test_huge_octet_range_is_bounded():
    parsed = parse_target('10.0-255.0-255.1-254')
    assert parsed['kind'] == 'octets'
    assert parsed['approximate'] is True
    assert len(parsed['intervals']) == 1


def test_split_targets_commas_and_newlines():
    assert split_targets('a.example.com, 10.0.0.1\n10.0.0.2,,\r\n') == ['a.example.com', '10.0.0.1', '10.0.0.2']
    assert split_targets(None) == []


def test_overlap_size():
    a = merge_intervals(parse_target('10.0.0.0/24')['intervals'])
    b = merge_intervals(parse_target('10.0.0.128-10.0.1.10')['intervals'])
    assert overlap_size(a, b) == 128
    assert overlap_size(a, merge_intervals(parse_target('10.0.2.0/24')['intervals'])) == 0
    v6 = merge_intervals(parse_target('2001:db8::/120')['intervals'])
    assert overlap_size(a, v6) == 0


def test_merge_adjacent_intervals():
    merged = merge_intervals(parse_target('10.0.0.0/25')['intervals'] + parse_target('10.0.0.128/25')['intervals'])
    assert merged == merge_intervals(parse_target('10.0.0.0/24')['intervals'])
