# SPDX-FileCopyrightText: 2026 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

from ipaddress import ip_address

import pytest
from donkey.util import (
    IpAddress,
    extract_base_domain,
    extract_subdomain_name,
    filter_ip_list,
    ip_type,
    is_subdomain,
    parse_ips,
)

V4 = ip_address("1.2.3.4")
V6 = ip_address("2001:db8::1")


def test_parse_ips_single_ipv4() -> None:
    assert parse_ips("1.2.3.4") == [V4]


def test_parse_ips_ipv4_and_ipv6() -> None:
    assert parse_ips("1.2.3.4,2001:db8::1") == [V4, V6]


def test_parse_ips_strips_whitespace() -> None:
    assert parse_ips(" 1.2.3.4 , 2001:db8::1 ") == [V4, V6]


def test_parse_ips_skips_invalid_entries() -> None:
    assert parse_ips("1.2.3.4,not-an-ip") == [V4]


def test_parse_ips_empty_string() -> None:
    assert parse_ips("") == []


def test_parse_ips_only_invalid_entries() -> None:
    assert parse_ips("foo,bar") == []


@pytest.mark.parametrize(
    ("ignore_ipv4", "ignore_ipv6", "expected"),
    [
        (False, False, [V4, V6]),
        (True, False, [V6]),
        (False, True, [V4]),
        (True, True, []),
    ],
)
def test_filter_ip_list(ignore_ipv4: bool, ignore_ipv6: bool, expected: list[IpAddress]) -> None:
    assert filter_ip_list([V4, V6], ignore_ipv4, ignore_ipv6) == expected


def test_ip_type() -> None:
    assert ip_type(V4) == "A"
    assert ip_type(V6) == "AAAA"


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("sub1.example.com", True),
        ("sub1.example.com.", True),
        ("sub1.example.com..", False),
        ("sub..example.com", False),
        (".sub1.example.com", False),
        ("example.com", False),
        ("com", False),
        ("", False),
    ],
)
def test_is_subdomain(domain: str, expected: bool) -> None:
    assert is_subdomain(domain) is expected


def test_extract_subdomain_name() -> None:
    assert extract_subdomain_name("sub1.example.com") == "sub1"
    assert extract_subdomain_name("sub1.example.com.") == "sub1"


def test_extract_base_domain() -> None:
    assert extract_base_domain("sub1.example.com") == "example.com"
    assert extract_base_domain("sub1.example.com.") == "example.com"


def test_extract_base_domain_keeps_extra_labels() -> None:
    assert extract_base_domain("a.b.example.com") == "b.example.com"
