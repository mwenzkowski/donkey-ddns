# SPDX-FileCopyrightText: 2026 Maximilian Wenzkowski
#
# SPDX-License-Identifier: GPL-3.0-or-later
import asyncio
import logging
from enum import Enum
from http import HTTPStatus
from ipaddress import IPv4Address, IPv6Address
from urllib.parse import quote

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


class FetchFailed:
    """Marker: the state of the record could not be determined."""


FETCH_FAILED = FetchFailed()


def _record_type_for(ip: IpAddress) -> DnsRecordType:
    if isinstance(ip, IPv4Address):
        return DnsRecordType.A
    if isinstance(ip, IPv6Address):
        return DnsRecordType.AAAA
    raise TypeError(f"Unsupported ip type: {type(ip)}")


class HetznerDnsClient:
    def __init__(self, api_token: str, zone_id: str, timeout_seconds: float) -> None:
        self._api_token = api_token
        self._zone_id = zone_id

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._session = aiohttp.ClientSession(timeout=timeout)
        self._session_closed = False

    async def _fetch_ip(  # noqa: PLR0911
        self, name: str, rtype: DnsRecordType
    ) -> IpAddress | FetchFailed | None:
        assert not self._session_closed
        logging.debug("Fetch rrset")
        try:
            async with self._session.get(
                f"{HETZNER_BASE_URL}/zones/{self._zone_id}/rrsets",
                params={"name": name, "type": rtype.value},
                headers={"Authorization": f"Bearer {self._api_token}"},
            ) as resp:
                if resp.status != HTTPStatus.OK:
                    text = await resp.text()
                    logging.error(f"Failed to fetch DNS records: {resp.status} {text}")
                    return FETCH_FAILED
                data = await resp.json()
        except Exception:
            logging.exception("Fetching DNS records failed")
            return FETCH_FAILED

        logging.debug(f"Response: {data}")
        try:
            rrsets = GetRRSetResponse.model_validate(data).rrsets
        except ValidationError:
            logging.exception("Unexpected response while fetching DNS records")
            return FETCH_FAILED

        if not rrsets:
            return None

        if len(rrsets) != 1:
            logging.error(f"Expected one rrset for {name} ({rtype.value}), got {len(rrsets)}")
            return FETCH_FAILED

        records = rrsets[0].records
        if not records:
            logging.error(f"The rrset for {name} ({rtype.value}) contains no records")
            return FETCH_FAILED

        return records[0].value

    async def fetch_ipv4(self, name: str) -> IPv4Address | FetchFailed | None:
        result = await self._fetch_ip(name=name, rtype=DnsRecordType.A)
        if result is None or result is FETCH_FAILED:
            return result

        if not isinstance(result, IPv4Address):
            logging.error(f"Expected an IPv4 address in the A record for {name}, got {result}")
            return FETCH_FAILED
        return result

    async def fetch_ipv6(self, name: str) -> IPv6Address | FetchFailed | None:
        result = await self._fetch_ip(name=name, rtype=DnsRecordType.AAAA)
        if result is None or result is FETCH_FAILED:
            return result

        if not isinstance(result, IPv6Address):
            logging.error(f"Expected an IPv6 address in the AAAA record for {name}, got {result}")
            return FETCH_FAILED
        return result

    async def _fetch_action(self, action_id: int) -> Action | None:
        assert not self._session_closed
        logging.debug("Fetch action")
        try:
            async with self._session.get(
                f"{HETZNER_BASE_URL}/zones/{self._zone_id}/actions/{action_id}",
                headers={"Authorization": f"Bearer {self._api_token}"},
            ) as resp:
                if resp.status != HTTPStatus.OK:
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

        async def waitloop() -> None:
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

    async def _post_action(self, url: str, payload: dict, description: str) -> bool:
        try:
            async with self._session.post(
                url,
                headers={"Authorization": f"Bearer {self._api_token}"},
                json=payload,
            ) as resp:
                if resp.status == HTTPStatus.CREATED:
                    data = await resp.json()
                else:
                    text = await resp.text()
                    logging.error(f"Failed to {description}: {resp.status} {text}")
                    return False
        except Exception:
            logging.exception(f"Failed to {description}")
            return False

        try:
            response = ActionResponse.model_validate(data)
        except ValidationError:
            logging.exception(f"Failed to {description}")
            return False

        try:
            return await self._wait_for_action_to_finish(response.action)
        except Exception:
            logging.exception(f"Failed to {description}")
            return False

    async def create_record(self, name: str, ip: IpAddress) -> bool:
        assert not self._session_closed
        rtype = _record_type_for(ip)

        payload = {
            "name": name,
            "type": rtype.value,
            "ttl": 60,
            "records": [{"value": str(ip)}],
        }
        logging.debug(f"Create record {payload}")

        result = await self._post_action(
            f"{HETZNER_BASE_URL}/zones/{self._zone_id}/rrsets",
            payload,
            f"create record {name} ({rtype.value})",
        )
        if result:
            logging.info(f"Created {name} ({rtype.value}) -> {ip}")

        return result

    async def update_record(self, name: str, ip: IpAddress) -> bool:
        assert not self._session_closed
        rtype = _record_type_for(ip)

        payload = {"records": [{"value": str(ip)}]}
        logging.debug(f"Update record {payload}")

        url = (
            f"{HETZNER_BASE_URL}/zones/{self._zone_id}/rrsets/"
            f"{quote(name, safe='')}/{rtype.value}/actions/set_records"
        )
        result = await self._post_action(url, payload, f"update record {name} ({rtype.value})")
        if result:
            logging.info(f"Updated {name} ({rtype.value}) -> {ip}")

        return result

    async def close_session(self) -> None:
        await self._session.close()
        self._session_closed = True
