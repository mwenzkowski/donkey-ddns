# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from ipaddress import IPv4Address, IPv6Address, ip_address

logger = logging.getLogger("util")

type IpAddress = IPv4Address | IPv6Address


def parse_ips(ip_param: str) -> list[IpAddress]:
    ips = []
    for part in ip_param.split(","):
        try:
            ip = ip_address(part.strip())
            ips.append(ip)
        except ValueError:
            logger.warning(f"Invalid IP skipped: '{part.strip()}'")
    return ips


def filter_ip_list(ips: list[IpAddress], ignore_ipv4, ignore_ipv6) -> list[IpAddress]:
    ignored_ip_versions = []
    if ignore_ipv4:
        ignored_ip_versions.append(4)
    if ignore_ipv6:
        ignored_ip_versions.append(6)

    return [ip for ip in ips if ip.version not in ignored_ip_versions]


def ip_type(ip: IPv4Address | IPv6Address) -> str:
    return "AAAA" if ip.version == 6 else "A"


def is_subdomain(domain: str) -> bool:
    # Remove any potential trailing dot (Trailing dot is allowed for domains)
    domain = domain.rstrip(".")

    parts = domain.split(".")
    return len(parts) > 2


def extract_subdomain_name(full_domain: str) -> str:
    assert is_subdomain(full_domain)
    return full_domain.split(".")[0]


def extract_base_domain(full_domain: str) -> str:
    assert is_subdomain(full_domain)
    return full_domain.split(".", maxsplit=1)[1]
