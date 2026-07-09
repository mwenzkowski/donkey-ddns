# SPDX-FileCopyrightText: 2026 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest
from donkey.config import Config, LogLevel
from pydantic import ValidationError

MINIMAL = {
    "hetzner_api_token": "token",
    "hetzner_zone_id": "zone",
    "base_domain": "example.com",
    "users": {"alice": {"password_hash": "hash", "sub_domains": {"sub1": {}}}},
}


def test_minimal_config_defaults() -> None:
    config = Config.model_validate(MINIMAL)
    assert config.listen_host is None
    assert config.listen_port == 8080  # noqa: PLR2004
    assert config.log_level is LogLevel.INFO
    assert config.hetzner_timeout_seconds == 30  # noqa: PLR2004


def test_unknown_top_level_key_rejected() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Config.model_validate(MINIMAL | {"listen_hosts": "127.0.0.1"})


def test_unknown_subdomain_key_rejected() -> None:
    users = {"alice": {"password_hash": "hash", "sub_domains": {"sub1": {"ttl": 60}}}}
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Config.model_validate(MINIMAL | {"users": users})


def test_empty_password_hash_rejected() -> None:
    users = {"alice": {"password_hash": "", "sub_domains": {"sub1": {}}}}
    with pytest.raises(ValidationError):
        Config.model_validate(MINIMAL | {"users": users})


@pytest.mark.parametrize("timeout", [0, -1, -0.5])
def test_non_positive_timeout_rejected(timeout: float) -> None:
    with pytest.raises(ValidationError):
        Config.model_validate(MINIMAL | {"hetzner_timeout_seconds": timeout})


@pytest.mark.parametrize(
    ("listen_host", "expected"),
    [
        (None, None),
        ([], None),
        (IPv4Address("127.0.0.1"), "127.0.0.1"),
        (IPv6Address("::1"), "::1"),
        ([IPv4Address("127.0.0.1"), IPv6Address("::1")], ["127.0.0.1", "::1"]),
    ],
)
def test_get_aiohttp_listen_hosts(
    listen_host: IPv4Address | IPv6Address | list[IPv4Address | IPv6Address] | None,
    expected: str | list[str] | None,
) -> None:
    config = Config.model_validate(MINIMAL | {"listen_host": listen_host})
    assert config.get_aiohttp_listen_hosts() == expected


def test_log_level_mapping() -> None:
    assert LogLevel.DEBUG.to_python_log_level() == logging.DEBUG
    assert LogLevel.INFO.to_python_log_level() == logging.INFO
    assert LogLevel.WARNING.to_python_log_level() == logging.WARNING
    assert LogLevel.ERROR.to_python_log_level() == logging.ERROR


def test_load_sample_config() -> None:
    sample = Path(__file__).parent.parent / "sample-config.toml"
    config = Config.load(sample)
    assert config.base_domain == "example.com"
    assert config.users["example_user"].sub_domains["sub2"].ignore_ipv6 is True


def test_load_missing_file_exits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        Config.load(tmp_path / "missing.toml")
    assert excinfo.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_load_invalid_syntax_exits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    broken = tmp_path / "broken.toml"
    broken.write_text('base_domain = "unterminated\n', encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        Config.load(broken)
    assert excinfo.value.code == 1
    assert "Syntax error" in capsys.readouterr().err


def test_load_invalid_value_exits(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    invalid = tmp_path / "invalid.toml"
    invalid.write_text('unknown_key = 1\nbase_domain = "example.com"\n', encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        Config.load(invalid)
    assert excinfo.value.code == 1
    assert "Unknown TOML key" in capsys.readouterr().err
