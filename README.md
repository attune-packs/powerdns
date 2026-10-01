# PowerDNS Authoritative Attune pack

Production-oriented actions for the PowerDNS Authoritative Server HTTP API.
This initial translation keeps the useful server, zone, record, notification,
rectification, export, and safe create-only restore behavior from the upstream
StackStorm pack while replacing its unpinned `python-powerdns` dependency with
a small direct API v1 client.

## Assumptions and setup

- PowerDNS Authoritative Server has `webserver=yes`, `api=yes`, and an API key.
- The API is exposed over HTTPS. Plain HTTP and disabled certificate validation
  are intentionally rejected. Restrict the PowerDNS webserver ACL as well.
- The URL ends in `/api/v1`, including any reverse-proxy prefix, for example
  `https://dns.example.net/pdns/api/v1`.
- Native PowerDNS Authoritative uses server ID `localhost`; proxies may expose
  other IDs.
- Zone and RRset names supplied as DNS names are absolute and end with `.`.

Create the pack-owned Attune Key `pack.powerdns.credentials` with an object value:

```json
{
  "api_url": "https://dns.example.net/api/v1",
  "api_key": "REDACTED",
  "connect_timeout_seconds": 5,
  "read_timeout_seconds": 30,
  "ca_bundle": "/optional/path/to/private-ca.pem"
}
```

`api_key` is sent only in `X-API-Key`. Errors never include response bodies,
request headers, or exception messages from unexpected remote failures. TLS
uses the system trust store unless `ca_bundle` is provided. Timeouts are bounded
to 1-30 seconds for connect and 1-300 seconds for response reads.

## Actions

| Action | Behavior |
|---|---|
| `powerdns.server_list` | Discover all API servers |
| `powerdns.server_get` | Get server/version details |
| `powerdns.zone_list` | Discover zones, optionally by exact name |
| `powerdns.zone_get` | Get a zone by opaque ID, optionally with RRsets |
| `powerdns.zone_create` | Create only when the exact zone name is absent |
| `powerdns.zone_delete` | Delete after `confirm: true` and exact name confirmation |
| `powerdns.rrset_get` | Look up one exact name/type RRset |
| `powerdns.rrset_upsert` | Idempotently replace a complete RRset |
| `powerdns.rrset_delete` | Idempotently delete one complete RRset after confirmation |
| `powerdns.zone_notify` | Trigger DNS NOTIFY without an HTTP request body |
| `powerdns.zone_rectify` | Rectify DNSSEC ordering data |
| `powerdns.zone_export` | Return API AXFR/BIND text as structured JSON |
| `powerdns.zone_backup` | Safe alias of `zone_export`; no arbitrary file writes |
| `powerdns.zone_import` | Create a missing zone from BIND text without overwrite |
| `powerdns.zone_restore` | Safe alias of `zone_import` |

Every action accepts a flat stdin JSON object and emits:

```json
{"operation":"server_get","result":{"server":{"id":"localhost"}}}
```

## Mutation semantics

`rrset_upsert` always uses PowerDNS `changetype: REPLACE`. Its `records` value
is the complete desired RRset: records not supplied are removed. An empty array
is rejected so an accidental empty upsert cannot delete the RRset. Use
`rrset_delete` with `confirm: true` for deletion. If `comments` is omitted,
existing comments are preserved; if present, it is the complete replacement
comment list, and `[]` removes all comments.

The client reads the current RRset before mutation and avoids the PATCH when
TTL, records, disabled flags, and supplied comments already match. RRsets are
unordered for this comparison. A successful mutation is read back from the
server and includes the resulting zone serial when available.

Zone create/import/restore are create-only. If an exact zone name already
exists, they return `changed: false`; they never convert that request into an
update. Zone deletion first reads the opaque ID and requires `confirm_name` to
exactly match the name returned by PowerDNS. Missing deletes are successful
no-ops.

The pack never sends `serial`, `notified_serial`, or `edited_serial`. PowerDNS
owns SOA serial processing. Set the zone's `soa_edit_api` policy appropriately
when creating it, and use `api_rectify: true` for automatic DNSSEC rectification
where suitable. Explicit rectification remains available and follows the API:
it fails for secondary/`Slave` zones and zones without DNSSEC.

## Backup and restore

The current API documents `GET .../zones/{zone_id}/export`, which returns an
AXFR/BIND-format JSON string, and zone creation with that text in the `zone`
field. `zone_export`/`zone_backup` therefore return `{format, zone_id,
zone_text}`. `zone_import`/`zone_restore` validate a 10 MiB input limit, check
that the target name is absent, and POST the text as a new zone.

There is no current in-place restore endpoint. This pack deliberately does not
delete or replace an existing zone during restore. It also does not claim that
zone export includes backend metadata, DNSSEC private keys, TSIG secrets, or
catalog configuration. Back those up through the appropriate backend and key
management procedures.

## API compatibility

The implementation was verified against the current PowerDNS Authoritative
OpenAPI definition version `0.0.20`, file revision
`3d17ec1fac0bcc81289b18a8dfa5f265b27e3563`. PowerDNS currently exposes no
pagination parameters for server or zone listing, so each discovery action
returns the complete API array. All path segments are percent-encoded and
query strings are delegated to `requests` encoding.

The API specification still uses `Master` and `Slave` zone-kind values even
where newer documentation uses primary/secondary terminology. The schemas use
the API's actual enum values for compatibility.

## Source inventory

Upstream: [StackStorm-Exchange/stackstorm-powerdns](https://github.com/StackStorm-Exchange/stackstorm-powerdns),
version `2.0.2`, revision `13879e0e66b29a466d82c1077a1d4abde69c0d3e`,
Apache-2.0. Exact provenance and API-reference revisions are in `SOURCE.json`.

## Conversion matrix

| Upstream behavior | Attune action | Fidelity | Notes |
|---|---|---|---|
| `get_servers` | `server_list`, `server_get` | adapted | Direct HTTP and structured results |
| `get_zones`, `get_zone`, `get_details` | `zone_list`, `zone_get` | adapted | Explicit opaque IDs and disabled records |
| `create_zone` | `zone_create` | adapted | Create-only; no ambiguous update flag |
| `delete_zone` | `zone_delete` | adapted | Name and boolean confirmation |
| `get_record`, `get_records` | `rrset_get`, `zone_get` | adapted | Exact current API filters |
| `create_records` | `rrset_upsert` | adapted | Explicit full `REPLACE`, idempotent preflight |
| `delete_records` | `rrset_delete` | adapted | Exact full-RRset delete only |
| `notify` | `zone_notify` | exact | Bodyless current endpoint |
| no upstream action | `zone_rectify` | added | Current documented DNSSEC endpoint |
| `backup` | `zone_export`, `zone_backup` | adapted | API export, no arbitrary path write |
| `restore_zone` | `zone_import`, `zone_restore` | adapted | BIND create import, refuses overwrite |
| `get_config`, `search`, `suggest_zone` | none | manual | Outside the quick-win operational scope |
| `run_all_actions`, aliases, workflow | none | manual | Test/demo orchestration is not shipped |

## Semantics gaps

- No live PowerDNS instance is bundled, so backend-specific behavior remains a
  live integration responsibility.
- Restore creates a missing zone only; existing-zone replacement is manual.
- Export does not include metadata or secret key material.
- This initial pack does not manage cryptokeys, TSIG keys, views, catalogs,
  metadata endpoints, cache, statistics, or secondary AXFR retrieval.
- PowerDNS version-specific support for `Producer` and `Consumer` depends on
  server and backend configuration.

## Runtime and testing

Python 3.10 or newer is required. Tests use deterministic mocked HTTP sessions
and make no DNS, PowerDNS, Attune API, or network calls.

```bash
python -m unittest discover -s tests -v
attune pack check .
attune pack test . --detailed
```
