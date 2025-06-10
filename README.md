<!--
SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Donkey Dynamic DNS server

**Donkey Dynamic DNS Server** is a focused DDNS (Dynamic DNS) server that is
compatible with the Speedport Smart 4 router. It updates DNS records
via [Hetzner's DNS API](https://dns.hetzner.com/api-docs) for a single zone,
allowing automatic updates of subdomains tied to changing IP addresses.

## Supported Update Request Format

Your router should be configured to send update requests in the following format:

```
GET /nic/update?hostname=subdomain.example.com&myip=1.2.3.4,2001:db8:85a3::8a2e:370:7334
Authorization: Basic base64(user:pass)
```

The server will authenticate and update the corresponding DNS record via Hetzner's API.

## Licensing

This work is licensed under multiple licences. Here is a brief summary:

- All original source code is licensed under GPL-3.0-or-later.
- All documentation is licensed under CC-BY-SA-4.0.
- Some configuration and data files are licensed under CC0-1.0.

For more accurate information, check the individual files.