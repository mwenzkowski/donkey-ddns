# SPDX-FileCopyrightText: 2025 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

import aiohttp
from pydantic import BaseModel

HETZNER_BASE_URL = "https://dns.hetzner.com/api/v1"

logger = logging.getLogger("hetzner_dns_client")


class DnsRecord(BaseModel):
    id: str
    type: str
    name: str
    value: str
    ttl: int | None = None
    zone_id: str


class DnsRecordsResponse(BaseModel):
    records: list[DnsRecord]


class DnsRecordCreateResponse(BaseModel):
    record: DnsRecord


class HetznerDnsClient:
    def __init__(self, api_token: str, zone_id: str, timeout_seconds: float) -> None:
        self._api_token = api_token
        self._zone_id = zone_id

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._session = aiohttp.ClientSession(timeout=timeout)
        self._session_closed = False

    async def fetch_dns_records(self) -> list[DnsRecord] | None:
        assert not self._session_closed
        logger.debug("Fetch DNS records")
        try:
            async with self._session.get(
                f"{HETZNER_BASE_URL}/records",
                headers={"Auth-API-Token": self._api_token},
            ) as resp:
                data = await resp.json()
                logger.debug(f"Response: {data}")
                all_records = DnsRecordsResponse(**data).records
                return [r for r in all_records if r.zone_id == self._zone_id]
        except Exception:
            logger.exception("Fetching DNS records failed")
            return None

    async def update_record(self, record: DnsRecord, new_ip: str) -> bool:
        assert not self._session_closed
        logger.debug(f"Update record {record} to {new_ip}")
        try:
            payload = {
                "value": new_ip,
                "type": record.type,
                "name": record.name,
                "zone_id": record.zone_id,
            }

            if record.ttl:
                payload["ttl"] = record.ttl

            async with self._session.put(
                f"{HETZNER_BASE_URL}/records/{record.id}",
                headers={
                    "Auth-API-Token": self._api_token,
                    "Content-Type": "application/json",
                },
                json=payload,
            ) as resp:
                if resp.status == 200:
                    logger.info(f"Updated {record.name} ({record.type}) -> {new_ip}")
                    return True
                else:
                    text = await resp.text()
                    logger.error(f"Failed update: {resp.status} {text}")
                    return False
        except Exception:
            logger.exception("Update exception")
            return False

    async def create_record(self, name: str, ip: str, rtype: str) -> bool:
        assert not self._session_closed
        try:
            payload = {
                "value": ip,
                "ttl": 60,
                "type": rtype,
                "name": name,
                "zone_id": self._zone_id,
            }
            logger.debug(f"Create record {payload}")

            async with self._session.post(
                f"{HETZNER_BASE_URL}/records",
                headers={"Auth-API-Token": self._api_token},
                json=payload,
            ) as resp:
                if resp.status == 200:
                    record = DnsRecordCreateResponse(**(await resp.json())).record
                    logger.info(
                        f"Created {record.name} ({record.type}) -> {record.value}"
                    )
                    return True
                else:
                    text = await resp.text()
                    logger.error(f"Failed create: {resp.status} {text}")
                    return False
        except Exception:
            logger.exception("Create exception")
            return False

    async def close_session(self) -> None:
        await self._session.close()
        self._session_closed = True
