"""Direct PowerDNS Authoritative HTTP API client and action dispatch."""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlsplit


class PowerDNSPackError(RuntimeError):
    """Safe operator-facing error which never includes credentials or response bodies."""


_MISSING = object()
_ZONE_KINDS = {"Native", "Master", "Slave", "Producer", "Consumer"}
_RR_TYPE = re.compile(r"^[A-Z][A-Z0-9-]{0,31}$")
_MAX_ZONE_TEXT_BYTES = 10 * 1024 * 1024


def _fetch_key(ref: str) -> dict[str, Any]:
    if not isinstance(ref, str) or not ref.strip():
        raise PowerDNSPackError("credential_key must be a non-empty string")
    try:
        import attune
        from attune.api_client.api.secrets import get_key
    except ImportError as exc:
        raise PowerDNSPackError("attune-sdk is required to resolve credential_key") from exc
    try:
        response = get_key.sync_detailed(ref, client=attune.context.client)
    except Exception as exc:
        raise PowerDNSPackError(f"unable to read credential Key {ref!r}") from exc
    status = int(response.status_code)
    if status == 404:
        raise PowerDNSPackError(f"credential Key {ref!r} was not found")
    if status >= 400 or not response.parsed:
        raise PowerDNSPackError(f"credential Key lookup failed with status {status}")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PowerDNSPackError("credential Key must contain a JSON object") from exc
    if not isinstance(value, dict):
        raise PowerDNSPackError("credential Key must contain an object")
    return value


def _required_string(values: Mapping[str, Any], name: str) -> str:
    value = values.get(name)
    if not isinstance(value, str) or not value.strip():
        raise PowerDNSPackError(f"{name} must be a non-empty string")
    return value


def _bounded_number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PowerDNSPackError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < minimum or result > maximum:
        raise PowerDNSPackError(f"{name} must be between {minimum:g} and {maximum:g}")
    return result


def _settings(config: Mapping[str, Any]) -> tuple[str, str, tuple[float, float], Any]:
    api_key = config.get("api_key")
    if not isinstance(api_key, str) or not api_key:
        raise PowerDNSPackError("credential Key requires api_key")
    api_url = config.get("api_url") or config.get("base_url")
    if not isinstance(api_url, str):
        raise PowerDNSPackError("credential Key requires api_url")
    parsed = urlsplit(api_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise PowerDNSPackError("api_url must be an HTTPS URL without user information")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise PowerDNSPackError("api_url contains an invalid port") from exc
    if parsed.query or parsed.fragment or not parsed.path.rstrip("/").endswith("/api/v1"):
        raise PowerDNSPackError("api_url must end in /api/v1 and contain no query or fragment")
    connect = _bounded_number(config.get("connect_timeout_seconds", 5), "connect_timeout_seconds", 1, 30)
    read = _bounded_number(config.get("read_timeout_seconds", 30), "read_timeout_seconds", 1, 300)
    if config.get("verify_tls") is False:
        raise PowerDNSPackError("TLS verification cannot be disabled")
    ca_bundle = config.get("ca_bundle")
    if ca_bundle is not None and (not isinstance(ca_bundle, str) or not ca_bundle.strip()):
        raise PowerDNSPackError("ca_bundle must be a non-empty path")
    if ca_bundle is not None and not os.path.isabs(ca_bundle):
        raise PowerDNSPackError("ca_bundle must be an absolute path")
    return api_key, api_url.rstrip("/"), (connect, read), ca_bundle or True


def _segment(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PowerDNSPackError(f"{name} must be a non-empty string")
    return quote(value, safe="")


def _fqdn(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or not value.endswith("."):
        raise PowerDNSPackError(f"{name} must be an absolute DNS name ending with a dot")
    if len(value.encode("utf-8")) > 255 or any(character.isspace() for character in value):
        raise PowerDNSPackError(f"{name} is not a valid absolute DNS name")
    return value


def _rr_type(value: Any) -> str:
    if not isinstance(value, str):
        raise PowerDNSPackError("record_type must be a string")
    result = value.upper()
    if not _RR_TYPE.fullmatch(result):
        raise PowerDNSPackError("record_type is invalid")
    return result


def _string_array(value: Any, name: str, *, fqdn: bool = False) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise PowerDNSPackError(f"{name} must be an array of non-empty strings")
    return [_fqdn(item, name) for item in value] if fqdn else list(value)


class PowerDNSClient:
    """Small direct client for the current Authoritative Server API v1."""

    def __init__(self, config: Mapping[str, Any], session: Any = None):
        import requests

        self.api_key, self.api_url, self.timeout, self.verify = _settings(config)
        self.session = session or requests.Session()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = _MISSING,
        allow_not_found: bool = False,
    ) -> Any:
        import requests

        kwargs: dict[str, Any] = {
            "headers": {"X-API-Key": self.api_key, "Accept": "application/json"},
            "params": params,
            "timeout": self.timeout,
            "verify": self.verify,
            "allow_redirects": False,
        }
        if body is not _MISSING:
            kwargs["headers"]["Content-Type"] = "application/json"
            kwargs["json"] = body
        try:
            response = self.session.request(method, self.api_url + path, **kwargs)
        except requests.Timeout as exc:
            raise PowerDNSPackError("PowerDNS request timed out") from exc
        except requests.RequestException as exc:
            raise PowerDNSPackError("PowerDNS request failed") from exc
        if allow_not_found and response.status_code == 404:
            return None
        if response.status_code < 200 or response.status_code >= 300:
            raise PowerDNSPackError(f"PowerDNS request failed with HTTP status {response.status_code}")
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except (ValueError, TypeError) as exc:
            raise PowerDNSPackError("PowerDNS returned an invalid JSON response") from exc

    @staticmethod
    def _expect(value: Any, expected: type, context: str) -> Any:
        if not isinstance(value, expected):
            raise PowerDNSPackError(f"PowerDNS returned an invalid {context} response")
        return value

    def servers(self) -> list[dict[str, Any]]:
        return self._expect(self.request("GET", "/servers"), list, "server list")

    def server(self, server_id: str) -> dict[str, Any]:
        value = self.request("GET", f"/servers/{_segment(server_id, 'server_id')}")
        return self._expect(value, dict, "server")

    def zones(self, server_id: str, zone: str | None = None, dnssec: bool = True) -> list[dict[str, Any]]:
        params: dict[str, str] = {"dnssec": str(dnssec).lower()}
        if zone is not None:
            params["zone"] = _fqdn(zone, "zone")
        path = f"/servers/{_segment(server_id, 'server_id')}/zones"
        return self._expect(self.request("GET", path, params=params), list, "zone list")

    def zone(self, server_id: str, zone_id: str, *, allow_not_found: bool = False, params: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
        path = f"/servers/{_segment(server_id, 'server_id')}/zones/{_segment(zone_id, 'zone_id')}"
        value = self.request("GET", path, params=params, allow_not_found=allow_not_found)
        if value is None and allow_not_found:
            return None
        return self._expect(value, dict, "zone")

    def create_zone(self, server_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        path = f"/servers/{_segment(server_id, 'server_id')}/zones"
        value = self.request("POST", path, body=dict(body))
        return self._expect(value, dict, "zone create")

    def mutate_zone(self, server_id: str, zone_id: str, method: str, suffix: str = "", body: Any = _MISSING, *, allow_not_found: bool = False) -> Any:
        path = f"/servers/{_segment(server_id, 'server_id')}/zones/{_segment(zone_id, 'zone_id')}{suffix}"
        return self.request(method, path, body=body, allow_not_found=allow_not_found)


def _server_id(params: Mapping[str, Any]) -> str:
    value = params.get("server_id", "localhost")
    if not isinstance(value, str) or not value.strip():
        raise PowerDNSPackError("server_id must be a non-empty string")
    return value


def _creation_body(params: Mapping[str, Any], *, zone_text: str | None = None) -> dict[str, Any]:
    name = _fqdn(params.get("name"), "name")
    kind = params.get("kind", "Native")
    if kind not in _ZONE_KINDS:
        raise PowerDNSPackError(f"kind must be one of {', '.join(sorted(_ZONE_KINDS))}")
    masters = _string_array(params.get("masters", []), "masters")
    if kind == "Slave" and not masters:
        raise PowerDNSPackError("masters must not be empty for a Slave zone")
    if kind != "Slave" and masters:
        raise PowerDNSPackError("masters is only valid for a Slave zone")
    body: dict[str, Any] = {"name": name, "kind": kind, "masters": masters}
    if params.get("nameservers") is not None:
        if kind == "Slave":
            raise PowerDNSPackError("nameservers must not be supplied for a Slave zone")
        body["nameservers"] = _string_array(params["nameservers"], "nameservers", fqdn=True)
    for field in ("dnssec", "api_rectify"):
        if params.get(field) is not None:
            if not isinstance(params[field], bool):
                raise PowerDNSPackError(f"{field} must be a boolean")
            body[field] = params[field]
    for field in ("soa_edit_api", "account", "catalog"):
        if params.get(field) is not None:
            body[field] = _required_string(params, field)
    if zone_text is not None:
        if kind == "Slave":
            raise PowerDNSPackError("zone_text must not be supplied for a Slave zone")
        body.pop("nameservers", None)
        body["zone"] = zone_text
    return body


def _create_if_absent(client: PowerDNSClient, params: Mapping[str, Any], *, import_zone: bool = False) -> dict[str, Any]:
    server_id = _server_id(params)
    zone_text = None
    if import_zone:
        zone_text = _required_string(params, "zone_text")
        if len(zone_text.encode("utf-8")) > _MAX_ZONE_TEXT_BYTES:
            raise PowerDNSPackError("zone_text exceeds the 10 MiB safety limit")
    body = _creation_body(params, zone_text=zone_text)
    existing = client.zones(server_id, body["name"], dnssec=True)
    if not all(isinstance(zone, dict) for zone in existing):
        raise PowerDNSPackError("PowerDNS returned an invalid zone list response")
    exact = [zone for zone in existing if zone.get("name") == body["name"]]
    if exact:
        return {"changed": False, "created": False, "reason": "zone already exists", "zone": exact[0]}
    created = client.create_zone(server_id, body)
    return {"changed": True, "created": True, "zone": created}


def _rrset(client: PowerDNSClient, server_id: str, zone_id: str, name: str, record_type: str, *, allow_missing_zone: bool = False) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    zone = client.zone(
        server_id,
        zone_id,
        allow_not_found=allow_missing_zone,
        params={"rrsets": "true", "rrset_name": name, "rrset_type": record_type, "include_disabled": "true"},
    )
    if zone is None:
        return None, None
    rrsets = zone.get("rrsets")
    if not isinstance(rrsets, list):
        raise PowerDNSPackError("PowerDNS zone response omitted the rrsets array")
    matches = [item for item in rrsets if isinstance(item, dict) and item.get("name") == name and item.get("type") == record_type]
    if len(matches) > 1:
        raise PowerDNSPackError("PowerDNS returned duplicate RRsets for one name and type")
    return zone, matches[0] if matches else None


def _records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise PowerDNSPackError("records must be a non-empty array; use rrset_delete to remove an RRset")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) - {"content", "disabled"}:
            raise PowerDNSPackError("each record must contain only content and optional disabled")
        content = item.get("content")
        disabled = item.get("disabled", False)
        if not isinstance(content, str) or not content or not isinstance(disabled, bool):
            raise PowerDNSPackError("record content must be non-empty and disabled must be boolean")
        key = (content, disabled)
        if key in seen:
            raise PowerDNSPackError("records must not contain duplicates")
        seen.add(key)
        result.append({"content": content, "disabled": disabled})
    return result


def _comments(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise PowerDNSPackError("comments must be an array")
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) - {"content", "account"}:
            raise PowerDNSPackError("each comment must contain only content and optional account")
        content = item.get("content")
        account = item.get("account")
        if not isinstance(content, str) or not content:
            raise PowerDNSPackError("comment content must be a non-empty string")
        comment = {"content": content}
        if account is not None:
            if not isinstance(account, str):
                raise PowerDNSPackError("comment account must be a string")
            comment["account"] = account
        result.append(comment)
    return result


def _canonical_records(value: Any) -> list[tuple[str, bool]]:
    if not isinstance(value, list):
        raise PowerDNSPackError("PowerDNS returned invalid RRset records")
    result = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("content"), str) or not isinstance(item.get("disabled", False), bool):
            raise PowerDNSPackError("PowerDNS returned invalid RRset records")
        result.append((item["content"], item.get("disabled", False)))
    return sorted(result)


def _canonical_comments(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        raise PowerDNSPackError("PowerDNS returned invalid RRset comments")
    result = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("content"), str) or not isinstance(item.get("account", ""), str):
            raise PowerDNSPackError("PowerDNS returned invalid RRset comments")
        result.append((item["content"], item.get("account", "")))
    return sorted(result)


def _export(client: PowerDNSClient, params: Mapping[str, Any]) -> dict[str, Any]:
    server_id = _server_id(params)
    zone_id = _required_string(params, "zone_id")
    value = client.mutate_zone(server_id, zone_id, "GET", "/export")
    if not isinstance(value, str):
        raise PowerDNSPackError("PowerDNS returned an invalid zone export response")
    return {"format": "bind", "zone_id": zone_id, "zone_text": value}


def execute_with_client(operation: str, params: Mapping[str, Any], client: PowerDNSClient) -> dict[str, Any]:
    server_id = _server_id(params)
    if operation == "server_list":
        return {"servers": client.servers()}
    if operation == "server_get":
        return {"server": client.server(server_id)}
    if operation == "zone_list":
        zone = params.get("zone")
        dnssec = params.get("dnssec", True)
        if not isinstance(dnssec, bool):
            raise PowerDNSPackError("dnssec must be a boolean")
        return {"zones": client.zones(server_id, zone, dnssec)}
    if operation == "zone_get":
        zone_id = _required_string(params, "zone_id")
        include_rrsets = params.get("include_rrsets", True)
        if not isinstance(include_rrsets, bool):
            raise PowerDNSPackError("include_rrsets must be a boolean")
        return {"zone": client.zone(server_id, zone_id, params={"rrsets": str(include_rrsets).lower(), "include_disabled": "true"})}
    if operation == "zone_create":
        return _create_if_absent(client, params)
    if operation in {"zone_import", "zone_restore"}:
        return _create_if_absent(client, params, import_zone=True)
    if operation in {"zone_export", "zone_backup"}:
        return _export(client, params)
    if operation == "zone_delete":
        zone_id = _required_string(params, "zone_id")
        if params.get("confirm") is not True:
            raise PowerDNSPackError("confirm must be true for zone deletion")
        expected_name = _fqdn(params.get("confirm_name"), "confirm_name")
        existing = client.zone(server_id, zone_id, allow_not_found=True, params={"rrsets": "false"})
        if existing is None:
            return {"changed": False, "deleted": False, "reason": "zone not found", "zone_id": zone_id}
        if existing.get("name") != expected_name:
            raise PowerDNSPackError("confirm_name does not match the zone returned by PowerDNS")
        client.mutate_zone(server_id, zone_id, "DELETE")
        return {"changed": True, "deleted": True, "zone_id": zone_id, "name": expected_name}
    if operation == "rrset_get":
        zone_id = _required_string(params, "zone_id")
        name = _fqdn(params.get("name"), "name")
        record_type = _rr_type(params.get("record_type"))
        zone, rrset = _rrset(client, server_id, zone_id, name, record_type)
        return {"found": rrset is not None, "rrset": rrset, "zone_id": zone_id, "serial": zone.get("serial") if zone else None}
    if operation == "rrset_upsert":
        zone_id = _required_string(params, "zone_id")
        name = _fqdn(params.get("name"), "name")
        record_type = _rr_type(params.get("record_type"))
        ttl = params.get("ttl")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1 or ttl > 2147483647:
            raise PowerDNSPackError("ttl must be an integer between 1 and 2147483647")
        records = _records(params.get("records"))
        comments = _comments(params["comments"]) if "comments" in params else None
        _, current = _rrset(client, server_id, zone_id, name, record_type)
        unchanged = current is not None and current.get("ttl") == ttl and _canonical_records(current.get("records")) == _canonical_records(records)
        if comments is not None:
            unchanged = unchanged and _canonical_comments(current.get("comments", [])) == _canonical_comments(comments)
        if unchanged:
            return {"changed": False, "rrset": current, "replacement_semantics": "full"}
        replacement: dict[str, Any] = {"name": name, "type": record_type, "ttl": ttl, "changetype": "REPLACE", "records": records}
        if comments is not None:
            replacement["comments"] = comments
        client.mutate_zone(server_id, zone_id, "PATCH", body={"rrsets": [replacement]})
        zone, updated = _rrset(client, server_id, zone_id, name, record_type)
        if updated is None:
            raise PowerDNSPackError("PowerDNS did not return the replaced RRset after update")
        return {"changed": True, "rrset": updated, "replacement_semantics": "full", "serial": zone.get("serial") if zone else None}
    if operation == "rrset_delete":
        zone_id = _required_string(params, "zone_id")
        name = _fqdn(params.get("name"), "name")
        record_type = _rr_type(params.get("record_type"))
        if params.get("confirm") is not True:
            raise PowerDNSPackError("confirm must be true for RRset deletion")
        zone, current = _rrset(client, server_id, zone_id, name, record_type, allow_missing_zone=True)
        if zone is None:
            return {"changed": False, "deleted": False, "reason": "zone not found", "zone_id": zone_id}
        if current is None:
            return {"changed": False, "deleted": False, "reason": "RRset not found", "zone_id": zone_id, "name": name, "record_type": record_type}
        deletion = {"name": name, "type": record_type, "changetype": "DELETE", "records": [], "comments": []}
        client.mutate_zone(server_id, zone_id, "PATCH", body={"rrsets": [deletion]})
        return {"changed": True, "deleted": True, "zone_id": zone_id, "name": name, "record_type": record_type}
    if operation in {"zone_notify", "zone_rectify"}:
        zone_id = _required_string(params, "zone_id")
        suffix = "/notify" if operation == "zone_notify" else "/rectify"
        value = client.mutate_zone(server_id, zone_id, "PUT", suffix)
        key = "notified" if operation == "zone_notify" else "rectified"
        return {key: True, "zone_id": zone_id, "response": value}
    raise PowerDNSPackError(f"unsupported PowerDNS operation {operation!r}")


def execute_action(operation: str, params: Mapping[str, Any]) -> dict[str, Any]:
    credential_key = params.get("credential_key", "pack.powerdns.credentials")
    config = _fetch_key(credential_key)
    return execute_with_client(operation, params, PowerDNSClient(config))
