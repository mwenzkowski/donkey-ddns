# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import tomllib
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Annotated, Dict, Set

from pydantic import BaseModel, PositiveInt, StringConstraints

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


class TomlUserSettings(BaseModel):
    password_hash: NonEmptyString
    sub_domains: Dict[NonEmptyString, dict]


@dataclass
class UserSettings:
    password_hash: str
    sub_domains: Set[str]

    @classmethod
    def from_toml(cls, toml_user_settings: TomlUserSettings):
        subdomains = set(toml_user_settings.sub_domains.keys())
        return cls(toml_user_settings.password_hash, subdomains)


class TomlConfig(BaseModel):
    listen_host: IpAddress | list[IpAddress] | None = None
    listen_port: PositiveInt = 8080

    log_level: LogLevel = LogLevel.INFO

    hetzner_api_token: NonEmptyString
    hetzner_zone_id: NonEmptyString
    hetzner_timeout_seconds: float = 30

    base_domain: NonEmptyString

    users: Dict[NonEmptyString, TomlUserSettings]

    @classmethod
    def load(cls, toml_file: Path) -> "TomlConfig":
        with open(toml_file, "rb") as f:
            data = tomllib.load(f)
        return cls.model_validate(data)


@dataclass
class Config:
    listen_host: IpAddress | list[IpAddress] | None
    listen_port: int

    log_level: LogLevel

    hetzner_api_token: str
    hetzner_zone_id: str
    hetzner_timeout_seconds: float

    base_domain: str

    users: Dict[str, UserSettings]

    @classmethod
    def from_toml(cls, toml_config: TomlConfig) -> "Config":
        converted_users = {
            user: UserSettings.from_toml(settings)
            for user, settings in toml_config.users.items()
        }
        raw = toml_config.model_dump()
        raw["users"] = converted_users
        return cls(**raw)

    @classmethod
    def load(cls, toml_file: Path) -> "Config":
        return cls.from_toml(TomlConfig.load(toml_file))

    def get_aiohttp_listen_hosts(self) -> str | list[str] | None:
        match self.listen_host:
            case None | []:
                return None
            case IPv4Address() | IPv6Address():
                return str(self.listen_host)
            case [*hosts]:
                return [str(host) for host in hosts]

        raise ValueError("Invalid listen_host value")
