# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import asyncio
import base64
import binascii
import logging
import sys
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from aiohttp import web
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from donkey.config import Config as DynDNSConfig
from donkey.hetzner_dns_client import HetznerDnsClient
from donkey.util import (
    extract_base_domain,
    extract_subdomain_name,
    ip_type,
    is_subdomain,
    parse_ips,
)

config_key = web.AppKey("config", DynDNSConfig)
password_hasher_key = web.AppKey("password_hasher", PasswordHasher)

logger = logging.getLogger("dyndns-server")


def setup_logger(config: DynDNSConfig) -> None:
    logging.basicConfig(
        level=config.log_level.to_python_log_level(),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


hetzner_dns_client_key = web.AppKey("hetzner_dns_client", HetznerDnsClient)


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
            logger.error(f"More than one matching {rtype} record: {matching_records}")
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
            logger.info(f"No IP change for {record.name} ({record.type})")
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

    logger.info(f"Request from {client_ip} ({auth_header}): {request.rel_url}")

    if not auth_header.startswith("Basic "):
        logger.warning(f"Update request rejected: invalid auth header ({auth_header})")
        return web.Response(text="badauth", status=401)

    try:
        b64_credentials = auth_header.split(" ")[1]
        credentials = base64.b64decode(b64_credentials).decode("utf-8")
        username, password = credentials.split(":", 1)
    except (IndexError, binascii.Error, UnicodeDecodeError):
        logger.warning(f"Update request rejected: invalid auth header ({auth_header})")
        return web.Response(text="badauth", status=401)

    config = request.app[config_key]
    user = config.get_user_by_name(username)

    if user is None:
        logger.warning(f"Update request rejected: invalid username ({username})")
        return web.Response(text="badauth", status=401)

    ph = request.app[password_hasher_key]
    try:
        await asyncio.to_thread(ph.verify, user.password_hash, password)
    except VerifyMismatchError:
        logger.warning(f"Update request rejected: password mismatch")
        return web.Response(text="badauth", status=401)

    query = request.query
    hostname = query.get("hostname")
    myip_param = query.get("myip", "")

    valid_hostname = hostname and is_subdomain(hostname)

    if not valid_hostname:
        logger.warning(f"Update request rejected: invalid hostname '{hostname}'")
        return web.Response(text="badagent", status=400)

    ip_list = parse_ips(myip_param)
    if not ip_list:
        logger.warning(f"Update request rejected: invalid myip param '{myip_param}'")
        return web.Response(text="badagent", status=400)

    base_domain = extract_base_domain(hostname)
    if base_domain != config.base_domain:
        logger.warning(
            f"Update request rejected: wrong base domain (got '{base_domain}', expected '{config.base_domain}'"
        )
        return web.Response(text="nohost", status=200)

    subdomain_name = extract_subdomain_name(hostname)

    if subdomain_name not in user.sub_domains:
        logger.warning(
            f"Update request rejected: hostname '{hostname}' is not in the list of updatable hostnames"
        )
        return web.Response(text="nohost", status=200)

    client = request.app[hetzner_dns_client_key]
    return await update_ips(client, hostname, ip_list)


async def handle_dyndns(request: web.Request) -> web.Response:
    try:
        return await handle_dyndns_internal(request)
    except Exception:
        logger.exception("Unhandled exception")
        return web.Response(text="911", status=500)


async def hetzner_dns_client_context(app: web.Application):
    config = app[config_key]
    app[hetzner_dns_client_key] = HetznerDnsClient(
        config.hetzner_api_token, config.hetzner_zone_id, config.hetzner_timeout_seconds
    )

    yield

    await app[hetzner_dns_client_key].close_session()


def create_app(config: DynDNSConfig):
    app = web.Application()
    app.router.add_get("/nic/update", handle_dyndns)

    app[config_key] = config
    app[password_hasher_key] = PasswordHasher()

    app.cleanup_ctx.append(hetzner_dns_client_context)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DynDNS server that updates subdomains of a single Hetzner DNS Zone"
    )
    parser.add_argument(
        "-c",
        "--config-file",
        default="~/.config/donkey-ddns/config.toml",
        help="The path to a config file to use for configuration",
    ),

    args = parser.parse_args()

    config_file = Path("config.toml")
    if args.config_file is not None:
        config_file = Path(args.config_file).expanduser()
    if not config_file.is_file():
        print(f"ERROR: config file {config_file} does not exists")
        print("Create it or select ")
        sys.exit(1)

    config = DynDNSConfig.load(config_file)
    setup_logger(config)

    host = config.get_aiohttp_listen_hosts()
    port = config.listen_port
    zone_id = config.hetzner_zone_id

    logging.info(
        f"Starting DynDNS server (zone ID: {zone_id}, base domain: {config.base_domain})"
    )
    web.run_app(create_app(config), host=host, port=port)


if __name__ == "__main__":
    main()
