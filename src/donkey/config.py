# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import tomllib
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, PositiveInt, StringConstraints, conlist, field_validator

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


class User(BaseModel):
    name: NonEmptyString
    password_hash: NonEmptyString
    sub_domains: list[NonEmptyString]


class Config(BaseModel):
    listen_host: IpAddress | list[IpAddress] | None = None
    listen_port: PositiveInt = 8080

    log_level: LogLevel = LogLevel.INFO

    hetzner_api_token: NonEmptyString
    hetzner_zone_id: NonEmptyString
    hetzner_timeout_seconds: float = 30

    base_domain: NonEmptyString
    users: conlist(User, min_length=1)

    @field_validator("users")
    def _no_duplicate_users(cls, users: list[User]):
        unique_names = {u.name for u in users}
        if len(users) != len(unique_names):
            raise ValueError("Duplicate usernames")
        return users

    @classmethod
    def load(cls, toml_file: Path) -> "Config":
        with open(toml_file, "rb") as f:
            data = tomllib.load(f)
        return Config.model_validate(data)

    def get_aiohttp_listen_hosts(self) -> str | list[str] | None:
        match self.listen_host:
            case None:
                return None
            case IPv4Address() | IPv6Address():
                return str(self.listen_host)
            case []:
                return None
            case [*hosts]:
                return [str(host) for host in hosts]

        raise ValueError("Invalid listen_host value")

    def get_user_by_name(self, name: str) -> User | None:
        matching_users = [u for u in self.users if u.name == name]
        assert len(matching_users) <= 1, "usernames must be unique"

        return matching_users[0] if matching_users else None
