# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import base64
import binascii
import getpass
import logging
import sys
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import AsyncGenerator

from aiohttp import web
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from donkey.config import Config as DynDNSConfig
from donkey.hetzner_dns_client import HetznerDnsClient
from donkey.util import (
    extract_base_domain,
    extract_subdomain_name,
    filter_ip_list,
    ip_type,
    is_subdomain,
    parse_ips,
)

DEFAULT_CONFIG_FILE = Path.home() / ".config" / "donkey-ddns" / "config.toml"

CONFIG_KEY = web.AppKey("config", DynDNSConfig)
HETZNER_DNS_CLIENT_KEY = web.AppKey("hetzner_dns_client", HetznerDnsClient)
PASSWORD_HASHER_KEY = web.AppKey("password_hasher", PasswordHasher)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


async def update_ips(
    client: HetznerDnsClient, hostname: str, ip_list: list[IPv4Address | IPv6Address]
) -> web.Response:
    assert ip_list, "ip_list must not be empty"
    subname = extract_subdomain_name(hostname)

    all_records = await client.fetch_dns_records()
    if all_records is None:
        return web.Response(text="911", status=500)

    target_records = [r for r in all_records if r.name == subname]

    response_lines = []

    for ip in ip_list:
        rtype = ip_type(ip)
        matching_records = [r for r in target_records if r.type == rtype]

        if len(matching_records) > 1:
            logging.error(f"More than one matching {rtype} record: {matching_records}")
            response_lines.append("911")
            continue

        if not matching_records:
            if await client.create_record(subname, str(ip), rtype):
                response_lines.append(f"good {ip}")
            else:
                response_lines.append("911")
            continue

        record = matching_records[0]

        if record.value == str(ip):
            logging.info(f"No IP change for {record.name} ({record.type})")
            response_lines.append(f"nochg {ip}")
            continue

        if await client.update_record(record, str(ip)):
            response_lines.append(f"good {ip}")
        else:
            response_lines.append("911")

    status = 200 if any((r != "911" for r in response_lines)) else 500
    return web.Response(text="\n".join(response_lines), status=status)


async def handle_dyndns_internal(request: web.Request) -> web.Response:
    client_ip = request.remote
    auth_header = request.headers.get("Authorization", "")

    logging.info(f"Request from {client_ip} ({auth_header}): {request.rel_url}")

    if not auth_header.startswith("Basic "):
        logging.warning(f"Update request rejected: invalid auth header ({auth_header})")
        return web.Response(text="badauth", status=401)

    try:
        b64_credentials = auth_header.split(" ")[1]
        credentials = base64.b64decode(b64_credentials).decode("utf-8")
        username, password = credentials.split(":", 1)
    except (IndexError, binascii.Error, UnicodeDecodeError):
        logging.warning(f"Update request rejected: invalid auth header ({auth_header})")
        return web.Response(text="badauth", status=401)

    config = request.app[CONFIG_KEY]
    user = config.users.get(username)

    if user is None:
        logging.warning(f"Update request rejected: invalid username ({username})")
        return web.Response(text="badauth", status=401)

    ph = request.app[PASSWORD_HASHER_KEY]
    try:
        await asyncio.to_thread(ph.verify, user.password_hash, password)
    except VerifyMismatchError:
        logging.warning(f"Update request rejected: password mismatch")
        return web.Response(text="badauth", status=401)

    hostname = request.query.get("hostname")
    myip_param = request.query.get("myip", "")

    valid_hostname = hostname and is_subdomain(hostname)

    if not valid_hostname:
        logging.warning(f"Update request rejected: invalid hostname '{hostname}'")
        return web.Response(text="badagent", status=400)

    ip_list = parse_ips(myip_param)
    if not ip_list:
        logging.warning(f"Update request rejected: invalid myip param '{myip_param}'")
        return web.Response(text="badagent", status=400)

    base_domain = extract_base_domain(hostname)
    if base_domain != config.base_domain:
        logging.warning(
            "Update request rejected: wrong base domain "
            f"(got '{base_domain}', expected ('{config.base_domain}')"
        )
        return web.Response(text="nohost", status=200)

    subdomain_name = extract_subdomain_name(hostname)
    subdomain_settings = user.sub_domains.get(subdomain_name)
    if subdomain_settings is None:
        logging.warning(
            "Update request rejected: "
            f"hostname '{hostname}' is not in the list of updatable hostnames"
        )
        return web.Response(text="nohost", status=200)

    ip_list = filter_ip_list(
        ip_list, subdomain_settings.ignore_ipv4, subdomain_settings.ignore_ipv6
    )
    if not ip_list:
        logging.warning(
            f"Update request rejected: All supplied IP addresses are ignored"
        )
        return web.Response(text="nohost", status=200)

    client = request.app[HETZNER_DNS_CLIENT_KEY]
    return await update_ips(client, hostname, ip_list)


async def handle_dyndns(request: web.Request) -> web.Response:
    try:
        return await handle_dyndns_internal(request)
    except Exception:
        logging.exception("Unhandled exception")
        return web.Response(text="911", status=500)


async def hetzner_dns_client_context(app: web.Application) -> AsyncGenerator[None]:
    config = app[CONFIG_KEY]
    app[HETZNER_DNS_CLIENT_KEY] = HetznerDnsClient(
        config.hetzner_api_token, config.hetzner_zone_id, config.hetzner_timeout_seconds
    )

    yield

    await app[HETZNER_DNS_CLIENT_KEY].close_session()


def create_app(config: DynDNSConfig) -> web.Application:
    app = web.Application()
    app.router.add_get("/nic/update", handle_dyndns)

    app[CONFIG_KEY] = config
    app[PASSWORD_HASHER_KEY] = PasswordHasher()

    app.cleanup_ctx.append(hetzner_dns_client_context)
    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DynDNS server that updates subdomains of a single Hetzner DNS Zone"
    )

    subparsers = parser.add_subparsers(
        dest="command", metavar="<COMMAND>", help="Sub-commands", required=True
    )

    serve_parser = subparsers.add_parser("serve", help="Start DynDNS server")
    serve_parser.add_argument(
        "-c",
        "--config-file",
        default=str(DEFAULT_CONFIG_FILE),
        help="The configuration file to use",
    ),

    create_password_hash_parser = subparsers.add_parser(
        "create-password-hash",
        help="Generate a password hash suitable for storing in the configuration file",
    )

    return parser.parse_args()


def command_serve(args: argparse.Namespace) -> None:
    config = DynDNSConfig.load(Path(args.config_file))

    logging.getLogger().setLevel(config.log_level.to_python_log_level())

    host = config.get_aiohttp_listen_hosts()
    port = config.listen_port
    zone_id = config.hetzner_zone_id

    logging.info(
        f"Starting DynDNS server (zone ID: {zone_id}, base domain: {config.base_domain})"
    )
    web.run_app(create_app(config), host=host, port=port)


def command_create_password_hash() -> None:
    password = getpass.getpass(prompt="Enter password: ")
    password_repeated = getpass.getpass(prompt="Repeat password: ")

    if password != password_repeated:
        print("Passwords don't match", file=sys.stderr)
        sys.exit(1)

    if len(password) == 0:
        print("Password cannot be empty", file=sys.stderr)
        sys.exit(1)

    ph = PasswordHasher()
    hash = ph.hash(password)
    print(f"\n{hash}")


def main() -> None:
    args = parse_args()

    if args.command == "serve":
        command_serve(args)
    elif args.command == "create-password-hash":
        command_create_password_hash()


if __name__ == "__main__":
    main()
