import hashlib
import importlib.util
import io
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

try:
    import requests  # noqa: F401
except ImportError:
    requests_stub = types.ModuleType("requests")
    requests_stub.Timeout = type("Timeout", (Exception,), {})
    requests_stub.RequestException = type("RequestException", (Exception,), {})
    requests_stub.Session = lambda: None
    sys.modules["requests"] = requests_stub


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import powerdns_client as client


class Response:
    def __init__(self, status_code=200, value=None, content=b"json"):
        self.status_code = status_code
        self._value = value
        self.content = content

    def json(self):
        if isinstance(self._value, Exception):
            raise self._value
        return self._value


class Session:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        return self.responses.pop(0)


def make_client(session):
    return client.PowerDNSClient(
        {"api_key": "top-secret", "api_url": "https://dns.example.invalid/proxy/api/v1"},
        session=session,
    )


class MetadataContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {}
        for path in sorted((ROOT / "actions").glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            cls.actions[path.stem] = text

    def test_expected_actions_exist(self):
        expected = {
            "server_list", "server_get", "zone_list", "zone_get", "zone_create",
            "zone_delete", "rrset_get", "rrset_upsert", "rrset_delete", "zone_notify",
            "zone_rectify", "zone_export", "zone_backup", "zone_import", "zone_restore",
        }
        self.assertEqual(expected, set(self.actions))

    def test_universal_flat_stdin_contract(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                for required in (
                    f"ref: powerdns.{name}", "runner_type: python", 'runtime_version: ">=3.10"',
                    "entry_point: powerdns_action.py", "parameter_delivery: stdin",
                    "parameter_format: json", "output_format: json",
                    "default_execution_permission_set_refs: [standard]", 'default: "pack.powerdns.credentials"',
                    "operation: {type: string, required: true}", "result: {type: object, required: true}",
                ):
                    self.assertIn(required, text)
                self.assertNotIn("  api_key:", text)
                self.assertNotIn("  data:", text)

    def test_destructive_actions_require_confirmation(self):
        for name in ("zone_delete", "rrset_delete"):
            self.assertIn("confirm: {type: boolean", self.actions[name])
            self.assertIn("const: true, required: true", self.actions[name])
        self.assertIn("confirm_name: {type: string", self.actions["zone_delete"])

    def test_upsert_schema_states_complete_replacement(self):
        definition = self.actions["rrset_upsert"]
        self.assertIn("Complete desired record list", definition)
        self.assertIn("min_items: 1", definition)
        self.assertIn("omit to preserve comments", definition)

    def test_source_metadata_and_readme_cover_provenance(self):
        source = json.loads((ROOT / "SOURCE.json").read_text(encoding="utf-8"))
        self.assertEqual("13879e0e66b29a466d82c1077a1d4abde69c0d3e", source["upstream"]["revision"])
        self.assertEqual("Apache-2.0", source["upstream"]["license"])
        self.assertEqual("3d17ec1fac0bcc81289b18a8dfa5f265b27e3563", source["api_reference"]["specification_revision"])
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in self.actions:
            self.assertIn(f"`powerdns.{name}`", readme)
        for phrase in ("full `REPLACE`", "never sends `serial`", "does not include metadata", "pagination parameters"):
            self.assertIn(phrase, readme)

    def test_license_is_exact_upstream_license(self):
        digest = hashlib.sha256((ROOT / "LICENSE").read_bytes()).hexdigest()
        self.assertEqual("55e051d5bf4c956102012a3e61cf61ecc7ef9253e630d6aebf2d56041946bb15", digest)


class ClientTests(unittest.TestCase):
    def test_settings_require_https_api_v1_tls_and_bounded_timeouts(self):
        valid = client._settings({
            "api_key": "x", "api_url": "https://dns.invalid/p/api/v1/",
            "connect_timeout_seconds": 4, "read_timeout_seconds": 20,
            "ca_bundle": "/ca.pem",
        })
        self.assertEqual(("x", "https://dns.invalid/p/api/v1", (4.0, 20.0), "/ca.pem"), valid)
        invalid = [
            {},
            {"api_key": "x", "api_url": "http://dns.invalid/api/v1"},
            {"api_key": "x", "api_url": "https://user@dns.invalid/api/v1"},
            {"api_key": "x", "api_url": "https://dns.invalid/not-v1"},
            {"api_key": "x", "api_url": "https://dns.invalid/api/v1?q=1"},
            {"api_key": "x", "api_url": "https://dns.invalid:bad/api/v1"},
            {"api_key": "x", "api_url": "https://dns.invalid/api/v1", "verify_tls": False},
            {"api_key": "x", "api_url": "https://dns.invalid/api/v1", "ca_bundle": "relative.pem"},
            {"api_key": "x", "api_url": "https://dns.invalid/api/v1", "read_timeout_seconds": 301},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(client.PowerDNSPackError):
                client._settings(value)

    def test_request_encodes_every_path_segment_and_uses_secret_header(self):
        session = Session(Response(value={"name": "example.org."}))
        api = make_client(session)
        api.zone("local proxy", "zone/id + value")
        method, url, kwargs = session.calls[0]
        self.assertEqual("GET", method)
        self.assertEqual("https://dns.example.invalid/proxy/api/v1/servers/local%20proxy/zones/zone%2Fid%20%2B%20value", url)
        self.assertEqual("top-secret", kwargs["headers"]["X-API-Key"])
        self.assertTrue(kwargs["verify"])
        self.assertEqual((5.0, 30.0), kwargs["timeout"])
        self.assertFalse(kwargs["allow_redirects"])

    def test_http_and_json_errors_are_safe(self):
        for response in (Response(500, {"error": "contains top-secret"}), Response(200, ValueError("top-secret"))):
            with self.subTest(status=response.status_code):
                with self.assertRaises(client.PowerDNSPackError) as caught:
                    make_client(Session(response)).servers()
                self.assertNotIn("top-secret", str(caught.exception))

    def test_server_and_zone_discovery_are_single_non_paginated_requests(self):
        session = Session(Response(value=[{"id": "localhost"}]), Response(value=[{"name": "example.org."}]))
        api = make_client(session)
        self.assertEqual("localhost", api.servers()[0]["id"])
        self.assertEqual("example.org.", api.zones("localhost", "example.org.", False)[0]["name"])
        self.assertEqual(2, len(session.calls))
        self.assertEqual({"dnssec": "false", "zone": "example.org."}, session.calls[1][2]["params"])

    def test_zone_create_is_idempotent_and_never_sends_serial_fields(self):
        existing = {"id": "example.org.", "name": "example.org.", "serial": 99}
        session = Session(Response(value=[existing]))
        result = client.execute_with_client("zone_create", {"name": "example.org.", "nameservers": ["ns1.example.org."]}, make_client(session))
        self.assertFalse(result["changed"])
        self.assertEqual(1, len(session.calls))

        session = Session(Response(value=[]), Response(201, {"id": "example.org.", "name": "example.org."}))
        result = client.execute_with_client("zone_create", {"name": "example.org.", "nameservers": ["ns1.example.org."], "soa_edit_api": "DEFAULT"}, make_client(session))
        self.assertTrue(result["created"])
        body = session.calls[1][2]["json"]
        self.assertEqual("DEFAULT", body["soa_edit_api"])
        for field in ("serial", "notified_serial", "edited_serial"):
            self.assertNotIn(field, body)

    def test_zone_delete_requires_boolean_and_matching_name(self):
        params = {"zone_id": "opaque", "confirm": True, "confirm_name": "example.org."}
        with self.assertRaisesRegex(client.PowerDNSPackError, "does not match"):
            client.execute_with_client("zone_delete", params, make_client(Session(Response(value={"name": "other.org."}))))
        session = Session(Response(value={"name": "example.org."}), Response(204, content=b""))
        result = client.execute_with_client("zone_delete", params, make_client(session))
        self.assertTrue(result["deleted"])
        self.assertEqual("DELETE", session.calls[1][0])
        self.assertNotIn("json", session.calls[1][2])
        missing = client.execute_with_client("zone_delete", params, make_client(Session(Response(404))))
        self.assertFalse(missing["changed"])

    def test_rrset_lookup_uses_current_api_filters(self):
        zone = {"serial": 2, "rrsets": [{"name": "www.example.org.", "type": "A", "ttl": 60, "records": []}]}
        session = Session(Response(value=zone))
        result = client.execute_with_client("rrset_get", {"zone_id": "example.org.", "name": "www.example.org.", "record_type": "a"}, make_client(session))
        self.assertTrue(result["found"])
        self.assertEqual({"rrsets": "true", "rrset_name": "www.example.org.", "rrset_type": "A", "include_disabled": "true"}, session.calls[0][2]["params"])

    def test_rrset_upsert_is_idempotent_for_unordered_records(self):
        current = {"name": "www.example.org.", "type": "A", "ttl": 300, "records": [{"content": "192.0.2.2", "disabled": False}, {"content": "192.0.2.1", "disabled": False}], "comments": []}
        session = Session(Response(value={"serial": 1, "rrsets": [current]}))
        params = {"zone_id": "example.org.", "name": "www.example.org.", "record_type": "A", "ttl": 300, "records": [{"content": "192.0.2.1"}, {"content": "192.0.2.2"}]}
        result = client.execute_with_client("rrset_upsert", params, make_client(session))
        self.assertFalse(result["changed"])
        self.assertEqual(1, len(session.calls))

    def test_rrset_upsert_sends_full_replace_and_reads_back_serial(self):
        old = {"rrsets": [{"name": "www.example.org.", "type": "A", "ttl": 60, "records": [{"content": "192.0.2.1", "disabled": False}], "comments": [{"content": "old"}]}]}
        updated_rrset = {"name": "www.example.org.", "type": "A", "ttl": 300, "records": [{"content": "192.0.2.2", "disabled": False}], "comments": []}
        session = Session(Response(value=old), Response(204, content=b""), Response(value={"serial": 42, "rrsets": [updated_rrset]}))
        params = {"zone_id": "example.org.", "name": "www.example.org.", "record_type": "A", "ttl": 300, "records": [{"content": "192.0.2.2"}], "comments": []}
        result = client.execute_with_client("rrset_upsert", params, make_client(session))
        self.assertTrue(result["changed"])
        self.assertEqual(42, result["serial"])
        replacement = session.calls[1][2]["json"]["rrsets"][0]
        self.assertEqual("REPLACE", replacement["changetype"])
        self.assertEqual([], replacement["comments"])
        self.assertEqual([{"content": "192.0.2.2", "disabled": False}], replacement["records"])

    def test_rrset_upsert_rejects_implicit_delete_and_duplicates(self):
        base = {"zone_id": "z", "name": "www.example.org.", "record_type": "A", "ttl": 60}
        for records in ([], [{"content": "192.0.2.1"}, {"content": "192.0.2.1"}]):
            with self.subTest(records=records), self.assertRaises(client.PowerDNSPackError):
                client.execute_with_client("rrset_upsert", {**base, "records": records}, make_client(Session()))

    def test_rrset_delete_has_no_ttl_and_is_idempotent(self):
        rrset = {"name": "www.example.org.", "type": "A", "ttl": 60, "records": [{"content": "192.0.2.1"}]}
        params = {"zone_id": "z", "name": "www.example.org.", "record_type": "A", "confirm": True}
        session = Session(Response(value={"rrsets": [rrset]}), Response(204, content=b""))
        result = client.execute_with_client("rrset_delete", params, make_client(session))
        self.assertTrue(result["deleted"])
        deletion = session.calls[1][2]["json"]["rrsets"][0]
        self.assertEqual({"name": "www.example.org.", "type": "A", "changetype": "DELETE", "records": [], "comments": []}, deletion)
        missing = client.execute_with_client("rrset_delete", params, make_client(Session(Response(value={"rrsets": []}))))
        self.assertFalse(missing["changed"])

    def test_notify_and_rectify_are_bodyless_puts(self):
        for operation, suffix in (("zone_notify", "/notify"), ("zone_rectify", "/rectify")):
            session = Session(Response(value={"result": "ok"}))
            client.execute_with_client(operation, {"zone_id": "example.org."}, make_client(session))
            method, url, kwargs = session.calls[0]
            self.assertEqual("PUT", method)
            self.assertTrue(url.endswith(suffix))
            self.assertNotIn("json", kwargs)
            self.assertNotIn("Content-Type", kwargs["headers"])

    def test_export_requires_json_string_and_import_is_create_only(self):
        session = Session(Response(value="$ORIGIN example.org.\n@ 300 IN SOA ns hostmaster 1 2 3 4 5\n"))
        result = client.execute_with_client("zone_export", {"zone_id": "opaque/id"}, make_client(session))
        self.assertEqual("bind", result["format"])
        self.assertIn("SOA", result["zone_text"])
        self.assertIn("opaque%2Fid/export", session.calls[0][1])

        text = "$ORIGIN example.org.\n"
        existing = client.execute_with_client("zone_restore", {"name": "example.org.", "zone_text": text}, make_client(Session(Response(value=[{"name": "example.org."}]))))
        self.assertFalse(existing["changed"])
        session = Session(Response(value=[]), Response(201, {"name": "example.org.", "id": "example.org."}))
        created = client.execute_with_client("zone_import", {"name": "example.org.", "zone_text": text, "soa_edit_api": "DEFAULT"}, make_client(session))
        self.assertTrue(created["changed"])
        body = session.calls[1][2]["json"]
        self.assertEqual(text, body["zone"])
        self.assertNotIn("nameservers", body)
        self.assertNotIn("serial", body)

    def test_fetch_key_accepts_object_and_redacts_lookup_failures(self):
        parsed = types.SimpleNamespace(data=types.SimpleNamespace(value='{"api_key":"secret","api_url":"https://dns.invalid/api/v1"}'))
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(sync_detailed=mock.Mock(return_value=types.SimpleNamespace(status_code=200, parsed=parsed)))
        modules = {
            "attune": fake_attune,
            "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules):
            self.assertEqual("secret", client._fetch_key("pack.powerdns.credentials")["api_key"])
        fake_secrets.get_key.sync_detailed.assert_called_once_with(
            "pack.powerdns.credentials", client=fake_attune.context.client
        )


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("powerdns_action_test", ROOT / "actions" / "powerdns_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def run_main(self, stdin, action="powerdns.server_list"):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"ATTUNE_ACTION": action}, clear=False), mock.patch("sys.stdin", io.StringIO(stdin)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            code = self.module.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_success_emits_declared_structure(self):
        with mock.patch.object(self.module, "execute_action", return_value={"servers": []}):
            code, stdout, stderr = self.run_main("{}")
        self.assertEqual(0, code)
        self.assertEqual({"operation": "server_list", "result": {"servers": []}}, json.loads(stdout))
        self.assertEqual("", stderr)

    def test_bad_input_and_unexpected_errors_do_not_leak(self):
        code, stdout, stderr = self.run_main("[]")
        self.assertEqual(1, code)
        self.assertEqual("", stdout)
        self.assertIn("JSON object", stderr)
        with mock.patch.object(self.module, "execute_action", side_effect=RuntimeError("top-secret response")):
            code, stdout, stderr = self.run_main("{}")
        self.assertEqual(1, code)
        self.assertNotIn("top-secret", stderr)
        code, stdout, stderr = self.run_main('{"broken":')
        self.assertEqual(1, code)
        self.assertEqual("", stdout)
        self.assertIn("invalid stdin JSON", stderr)


if __name__ == "__main__":
    unittest.main()
