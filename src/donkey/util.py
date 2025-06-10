# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from ipaddress import IPv4Address, IPv6Address, ip_address

from donkey.config import LogLevel

logger = logging.getLogger("util")


def convert_log_level(level: LogLevel) -> int:
    match level:
        case LogLevel.DEBUG:
            return logging.DEBUG
        case LogLevel.INFO:
            return logging.INFO
        case LogLevel.WARNING:
            return logging.WARNING
        case LogLevel.ERROR:
            return logging.ERROR

    raise ValueError("Invalid log level")


def parse_ips(ip_param: str) -> list[IPv4Address | IPv6Address]:
    ips = []
    for part in ip_param.split(","):
        try:
            ip = ip_address(part.strip())
            ips.append(ip)
        except ValueError:
            logger.warning(f"Invalid IP skipped: '{part.strip()}'")
    return ips


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
