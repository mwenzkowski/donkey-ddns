# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Annotated, Dict

from pydantic import BaseModel, PositiveInt, StringConstraints
from tomlkit.toml_file import TOMLFile

type NonEmptyString = Annotated[str, StringConstraints(min_length=1)]


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    def to_python_log_level(self) -> int:
        match self:
            case LogLevel.DEBUG:
                return logging.DEBUG
            case LogLevel.INFO:
                return logging.INFO
            case LogLevel.WARNING:
                return logging.WARNING
            case LogLevel.ERROR:
                return logging.ERROR

        raise ValueError("Invalid log level")


type IpAddress = IPv4Address | IPv6Address


class SubdomainSettings(BaseModel):
    ignore_ipv4: bool = False
    ignore_ipv6: bool = False


class UserSettings(BaseModel):
    password_hash: NonEmptyString
    sub_domains: Dict[NonEmptyString, SubdomainSettings]


class Config(BaseModel):
    listen_host: IpAddress | list[IpAddress] | None = None
    listen_port: PositiveInt = 8080

    log_level: LogLevel = LogLevel.INFO

    hetzner_api_token: NonEmptyString
    hetzner_zone_id: NonEmptyString
    hetzner_timeout_seconds: float = 30

    base_domain: NonEmptyString

    users: Dict[NonEmptyString, UserSettings]

    @classmethod
    def load(cls, toml_file: Path) -> "Config":
        data = TOMLFile(toml_file).read()
        return cls.model_validate(data.unwrap())

    def get_aiohttp_listen_hosts(self) -> str | list[str] | None:
        match self.listen_host:
            case None | []:
                return None
            case IPv4Address() | IPv6Address():
                return str(self.listen_host)
            case [*hosts]:
                return [str(host) for host in hosts]

        raise ValueError("Invalid listen_host value")
