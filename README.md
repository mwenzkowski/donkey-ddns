<!--
SPDX-FileCopyrightText: 2026 Maximilian Wenzkowski

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Donkey Dynamic DNS server

**Donkey Dynamic DNS Server** is a DDNS (Dynamic DNS) server that is
compatible with the Speedport Smart 4 router. It updates A and AAAA records
in a single DNS zone via the [Hetzner Cloud API](https://docs.hetzner.cloud/),
so subdomains can follow a changing home IP address.

## Update request format

Configure the router to send update requests in this form:

```
GET /nic/update?hostname=sub1.example.com&myip=1.2.3.4,2001:db8::1
Authorization: Basic base64(user:password)
```

- `hostname` is one subdomain of the configured base domain. A single
  trailing dot is accepted.
- `myip` is required and takes one or more comma separated addresses (IPv4,
  IPv6, or both). Requests without a usable address are answered with
  `badagent`. The server does not fall back to the connection's source
  address: behind the TLS proxy described below, that address belongs to
  the proxy, not to the router.

Responses use the DynDNS2 protocol words: `good`, `nochg`, `badauth`,
`badagent`, `nohost`, and `911`.

## Installation

The project is managed with [uv](https://docs.astral.sh/uv/) and needs
Python 3.13.

```sh
git clone https://github.com/mwenzkowski/donkey-ddns
cd donkey-ddns
uv sync
```

## Configuration

`sample-config.toml` in the repository root documents every option. The
server needs:

- `hetzner_api_token`: an API token for the Hetzner Cloud project that owns
  the zone
- `hetzner_zone_id`: the ID of the DNS zone
- `base_domain`: the domain whose subdomains the server manages, e.g.
  `example.com`
- one `users.<name>` entry per account, with an argon2 password hash and
  the subdomains that account may update

Generate a password hash for the config file with:

```sh
uv run donkey-ddns create-password-hash
```

Per subdomain, `ignore_ipv4` and `ignore_ipv6` drop one address family from
updates. Created records use a TTL of 60 seconds.

## Running

```sh
uv run donkey-ddns serve -c config.toml
```

Without `-c`, the server reads `~/.config/donkey-ddns/config.toml`. It
listens on port 8080 by default; `listen_host` and `listen_port` change
that.

## Deployment

The server speaks plain HTTP, and HTTP Basic auth transmits the password
base64 encoded on every request. Run it behind a reverse proxy that
terminates TLS. The server also does not limit authentication attempts,
and each attempt costs it one argon2 verification, so rate limiting
belongs in the proxy as well.

## Licensing

This work is licensed under multiple licences. Here is a brief summary:

- All original source code is licensed under GPL-3.0-or-later.
- All documentation is licensed under CC-BY-SA-4.0.
- Some configuration and data files are licensed under CC0-1.0.

For more accurate information, check the individual files.
