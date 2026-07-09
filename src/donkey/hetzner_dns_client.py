# SPDX-FileCopyrightText: 2026 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import logging
from enum import Enum
from ipaddress import IPv4Address, IPv6Address

import aiohttp
from pydantic import BaseModel, ValidationError

from donkey.util import IpAddress

HETZNER_BASE_URL = "https://api.hetzner.cloud/v1"


class DnsRecordType(Enum):
    A = "A"
    AAAA = "AAAA"


class RRSetRecord(BaseModel):
    value: IpAddress


class RRSet(BaseModel):
    records: list[RRSetRecord]


class GetRRSetResponse(BaseModel):
    rrsets: list[RRSet]


class ActionStatus(Enum):
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"


class ActionError(BaseModel):
    code: str
    message: str


class Action(BaseModel):
    id: int
    status: ActionStatus
    error: ActionError | None


class ActionResponse(BaseModel):
    action: Action


class HetznerDnsClient:
    def __init__(self, api_token: str, zone_id: str, timeout_seconds: float) -> None:
        self._api_token = api_token
        self._zone_id = zone_id

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._session = aiohttp.ClientSession(timeout=timeout)
        self._session_closed = False

    async def _fetch_ip(self, name: str, rtype: DnsRecordType) -> IpAddress | None:
        assert not self._session_closed
        logging.debug("Fetch rrset")
        try:
            async with self._session.get(
                f"{HETZNER_BASE_URL}/zones/{self._zone_id}/rrsets?name={name}&type={rtype.value}",
                headers={"Authorization": f"Bearer {self._api_token}"},
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    logging.error(f"Failed to fetch DNS records: {resp.status} {text}")
                    return None
                data = await resp.json()
        except Exception:
            logging.exception("Fetching DNS records failed")
            return None

        logging.debug(f"Response: {data}")
        try:
            rrsets = GetRRSetResponse.model_validate(data).rrsets
        except ValidationError:
            logging.exception("Unexpected response while fetching DNS records")
            return None

        if not rrsets:
            return None

        assert len(rrsets) == 1
        records = rrsets[0].records

        return records[0].value

    async def fetch_ipv4(self, name: str) -> IPv4Address | None:
        result = await self._fetch_ip(name=name, rtype=DnsRecordType.A)
        if not result:
            return None

        assert isinstance(result, IPv4Address)
        return result

    async def fetch_ipv6(self, name: str) -> IPv6Address | None:
        result = await self._fetch_ip(name=name, rtype=DnsRecordType.AAAA)
        if not result:
            return None

        assert isinstance(result, IPv6Address)
        return result

    async def _fetch_action(self, action_id: int) -> Action | None:
        assert not self._session_closed
        logging.debug("Fetch action")
        try:
            async with self._session.get(
                f"{HETZNER_BASE_URL}/zones/{self._zone_id}/actions/{action_id}",
                headers={"Authorization": f"Bearer {self._api_token}"},
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    logging.error(f"Failed to fetch action: {resp.status} {text}")
                    return None
                data = await resp.json()
        except Exception:
            logging.exception("Fetching action failed")
            return None

        logging.debug(f"Response: {data}")

        try:
            action = ActionResponse.model_validate(data).action
        except ValidationError:
            logging.exception("Unexpected response while fetching action")
            return None

        return action

    async def _wait_for_action_to_finish(self, action: Action) -> bool:
        assert not self._session_closed

        async def waitloop():
            nonlocal action
            while action is not None and action.status == ActionStatus.RUNNING:
                await asyncio.sleep(1)
                action = await self._fetch_action(action.id)

        await asyncio.wait_for(waitloop(), timeout=60)

        if action is None:
            logging.error("Failed to poll action status")
            return False

        if action.status == ActionStatus.SUCCESS:
            return True

        assert action.status == ActionStatus.ERROR
        if action.error is not None:
            logging.error(f"Failed action: {action.error.message} ({action.error.code})")
        else:
            logging.error("Failed action: unknown error")
        return False

    async def create_record(self, name: str, ip: IpAddress) -> bool:
        assert not self._session_closed

        if isinstance(ip, IPv4Address):
            rtype = DnsRecordType.A
        elif isinstance(ip, IPv6Address):
            rtype = DnsRecordType.AAAA
        else:
            raise TypeError(f"Unsupported ip type: {type(ip)}")

        payload = {
            "name": name,
            "type": rtype.value,
            "ttl": 60,
            "records": [{"value": str(ip)}],
        }
        logging.debug(f"Create record {payload}")

        try:
            async with self._session.post(
                f"{HETZNER_BASE_URL}/zones/{self._zone_id}/rrsets",
                headers={"Authorization": f"Bearer {self._api_token}"},
                json=payload,
            ) as resp:
                if resp.status == 201:
                    data = await resp.json()
                else:
                    text = await resp.text()
                    logging.error(f"Failed create: {resp.status} {text}")
                    return False
        except Exception:
            logging.exception("Create exception")
            return False

        try:
            response = ActionResponse.model_validate(data)
        except ValidationError:
            logging.exception("Create exception")
            return False

        try:
            result = await self._wait_for_action_to_finish(response.action)
        except Exception:
            logging.exception("Create exception")
            return False

        if result:
            logging.info(f"Created {name} ({rtype}) -> {str(ip)}")

        return result

    async def update_record(self, name: str, ip: IpAddress) -> bool:
        assert not self._session_closed

        if isinstance(ip, IPv4Address):
            rtype = DnsRecordType.A
        elif isinstance(ip, IPv6Address):
            rtype = DnsRecordType.AAAA
        else:
            raise TypeError(f"Unsupported ip type: {type(ip)}")

        payload = {"records": [{"value": str(ip)}]}
        logging.debug(f"Update record {payload}")

        try:
            async with self._session.post(
                f"{HETZNER_BASE_URL}/zones/{self._zone_id}/rrsets/{name}/{rtype.value}/actions/set_records",
                headers={"Authorization": f"Bearer {self._api_token}"},
                json=payload,
            ) as resp:
                if resp.status == 201:
                    data = await resp.json()
                else:
                    text = await resp.text()
                    logging.error(f"Failed create: {resp.status} {text}")
                    return False
        except Exception:
            logging.exception("Create exception")
            return False

        try:
            response = ActionResponse.model_validate(data)
        except ValidationError:
            logging.exception("Create exception")
            return False

        try:
            result = await self._wait_for_action_to_finish(response.action)
        except Exception:
            logging.exception("Create exception")
            return False

        if result:
            logging.info(f"Created {name} ({rtype}) -> {str(ip)}")

        return result

    async def close_session(self) -> None:
        await self._session.close()
        self._session_closed = True
