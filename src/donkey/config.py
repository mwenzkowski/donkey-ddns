# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import sys
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Annotated, Dict

import tomlkit
from pydantic import (
    BaseModel,
    ConfigDict,
    PositiveInt,
    StringConstraints,
    ValidationError,
)
from tomlkit import TOMLDocument
from tomlkit.exceptions import KeyAlreadyPresent, ParseError

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

    model_config = ConfigDict(extra="forbid")


class UserSettings(BaseModel):
    password_hash: NonEmptyString
    sub_domains: Dict[NonEmptyString, SubdomainSettings]

    model_config = ConfigDict(extra="forbid")


class Config(BaseModel):
    listen_host: IpAddress | list[IpAddress] | None = None
    listen_port: PositiveInt = 8080

    log_level: LogLevel = LogLevel.INFO

    hetzner_api_token: NonEmptyString
    hetzner_zone_id: NonEmptyString
    hetzner_timeout_seconds: float = 30

    base_domain: NonEmptyString

    users: Dict[NonEmptyString, UserSettings]

    model_config = ConfigDict(extra="forbid")

    @staticmethod
    def _print_parse_error(error: ParseError, toml_path: Path, toml_text: str) -> None:
        lines = toml_text.splitlines()
        error_line = (
            lines[error.line - 1]
            if 0 <= error.line - 1 < len(lines)
            else "<unknown line>"
        )
        caret_line = " " * (error.col - 1) + "^"

        print(
            f"Syntax error while parsing config file {toml_path}:\n",
            file=sys.stderr,
        )
        print(f"    {error_line}\n    {caret_line}\n", file=sys.stderr)
        print(f"{error}", file=sys.stderr)

    @staticmethod
    def _print_validation_error(
        error: ValidationError, toml_path: Path, toml_text: str, toml_doc: TOMLDocument
    ) -> None:
        print(
            f"Config file {toml_path} is invalid:\n",
            file=sys.stderr,
        )

        for e in error.errors():
            loc = e["loc"]
            location_path = ".".join((map(str, loc)))

            if e["type"] == "extra_forbidden":
                msg = "Unknown TOML key"
            else:
                msg = e["msg"]

            print(f"    {location_path}: {msg}", file=sys.stderr)

    @classmethod
    def load(cls, toml_path: Path) -> "Config":
        try:
            toml_text = toml_path.read_text(encoding="utf-8")

        except FileNotFoundError:
            print(f"Config file not found: {toml_path}", file=sys.stderr)
            sys.exit(1)

        except PermissionError:
            print(
                f"Permission denied when reading config file: {toml_path}",
                file=sys.stderr,
            )
            sys.exit(1)

        except OSError as e:
            print(f"OS error while reading config file: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            toml_doc = tomlkit.loads(toml_text)
        except ParseError as e:
            cls._print_parse_error(e, toml_path, toml_text)
            sys.exit(1)
        except KeyAlreadyPresent as e:
            print(f"Duplicate key error in TOML file {toml_path}: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            config = cls.model_validate(toml_doc.unwrap())
        except ValidationError as e:
            cls._print_validation_error(e, toml_path, toml_text, toml_doc)
            sys.exit(1)

        return config

    def get_aiohttp_listen_hosts(self) -> str | list[str] | None:
        match self.listen_host:
            case None | []:
                return None
            case IPv4Address() | IPv6Address():
                return str(self.listen_host)
            case [*hosts]:
                return [str(host) for host in hosts]

        raise ValueError("Invalid listen_host value")
