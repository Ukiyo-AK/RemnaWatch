from contextlib import redirect_stdout, redirect_stderr
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch, mock_open
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from remnawatch.auth import NodeAuth, generate_node_credentials, resolve_auth, main as issue_cli
from remnawatch.api import make_server
from remnawatch.store import Store
from remnawatch.__main__ import main as service_main


NODE_ID = "59cf9ada-b568-4513-8582-923576b05ef3"
OTHER_ID = "ab530bb6-acd2-4c15-8737-9c0b6c9fe088"


class CredentialTests(unittest.TestCase):
    def test_generator_per_node_secret_entropy_and_parse(self):
        with patch("remnawatch.auth.secrets.token_urlsafe", return_value="A" * 43) as source:
            issued = generate_node_credentials(NODE_ID)
        source.assert_called_once_with(32)
        self.assertEqual(issued["node_id"], NODE_ID)
        self.assertEqual(NodeAuth(issued["token"]).node_id, NODE_ID)
        self.assertNotIn(issued["token"], repr(NodeAuth(issued["token"])))

    def test_new_identity_and_rotation_are_distinct(self):
        first, second = generate_node_credentials(), generate_node_credentials()
        self.assertNotEqual(first["node_id"], second["node_id"])
        self.assertNotEqual(first["token"], second["token"])
        rotated = generate_node_credentials(first["node_id"])
        self.assertEqual(rotated["node_id"], first["node_id"])
        self.assertFalse(NodeAuth(rotated["token"]).accepts(["Bearer " + first["token"]]))

    def test_rejects_invalid_identity_or_versioned_encoding(self):
        for identity in ("node-1", NODE_ID.upper(), "00000000-0000-0000-0000-000000000000", "", 123):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                generate_node_credentials(identity)
        for token in ("rw_node_v1." + NODE_ID + "." + "A" * 42,
                      "rw_node_v1." + NODE_ID + "." + "A" * 42 + "B"):
            with self.assertRaises(ValueError):
                NodeAuth(token)

    def test_config_token_wins_over_stale_environment(self):
        issued = generate_node_credentials(NODE_ID)
        auth = resolve_auth({"auth": issued}, {"REMNAWATCH_API_TOKEN": "old" * 32})
        self.assertTrue(auth.accepts(["Bearer " + issued["token"]]))
        self.assertFalse(auth.accepts(["Bearer " + "old" * 32]))

    def test_only_token_needs_to_be_pasted_and_environment_stays_supported(self):
        issued = generate_node_credentials(NODE_ID)
        self.assertEqual(resolve_auth({"auth": {"token": issued["token"]}}, {}).node_id, NODE_ID)
        self.assertEqual(resolve_auth({}, {"REMNAWATCH_API_TOKEN": issued["token"]}).node_id, NODE_ID)
        self.assertIsNone(resolve_auth({"auth": {"token": ""}}, {"REMNAWATCH_API_TOKEN": "a" * 32}).node_id)

    def test_invalid_config_never_silently_falls_back(self):
        issued = generate_node_credentials(NODE_ID)
        for section in ({"token": "short"}, {"token": "rw_node_v1.invalid"}, {"token": 123},
                        {"token": issued["token"], "node_id": OTHER_ID}, {"token": "a" * 32},
                        {"token": issued["token"], "secret_extra": "x"}, [], None):
            with self.subTest(section=type(section).__name__), self.assertRaises(ValueError):
                resolve_auth({"auth": section}, {"REMNAWATCH_API_TOKEN": "a" * 32})

    def test_missing_auth_and_control_characters_rejected_without_secret_in_error(self):
        with self.assertRaises(ValueError):
            resolve_auth({}, {})
        for value in ("a" * 31, "é" * 32, "a" * 513, "a" * 32 + "\x00", "a" * 32 + "\n"):
            with self.assertRaises(ValueError) as caught:
                NodeAuth(value)
            self.assertNotIn(value, str(caught.exception))

    def test_only_exact_single_bearer_header_is_accepted(self):
        issued = generate_node_credentials(NODE_ID)
        auth = NodeAuth(issued["token"])
        valid = "Bearer " + issued["token"]
        self.assertTrue(auth.accepts([valid]))
        for headers in ([], [valid, valid], [valid + " "], [issued["token"]], ["Basic " + issued["token"]]):
            self.assertFalse(auth.accepts(headers))

    def test_generator_cli_json_and_invalid_uuid(self):
        output = io.StringIO()
        with redirect_stdout(output):
            issue_cli(["issue-token", "--node-id", NODE_ID])
        issued = json.loads(output.getvalue())
        self.assertEqual(issued["node_id"], NODE_ID)
        self.assertEqual(resolve_auth({"auth": issued}, {}).node_id, NODE_ID)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            issue_cli(["issue-token", "--node-id", "not-a-uuid"])

    def test_bad_auth_fails_before_any_history_mutation(self):
        with patch("sys.argv", ["remnawatch", "--config", "config.json"]), patch("builtins.open", mock_open(read_data='{"domains":{"enabled":false},"auth":{"token":"bad"}}')), patch("remnawatch.__main__.Store") as store:
            with self.assertRaises(ValueError):
                service_main()
        store.assert_not_called()


class EnrollmentHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "node.sqlite")
        self.issued = generate_node_credentials(NODE_ID)
        self.server = make_server(self.store, resolve_auth({"auth": self.issued}, {}), ("127.0.0.1", 0))
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.store.close()
        self.temp.cleanup()

    def request(self, path, token=None, data=None):
        headers = {"Authorization": "Bearer " + token} if token else {}
        return urlopen(Request(self.base + path, headers=headers, data=data))

    def test_main_server_connection_verification_contains_no_secret(self):
        with self.request("/v1/node", self.issued["token"]) as response:
            raw = response.read().decode()
            result = json.loads(raw)
            self.assertEqual(result["node_id"], NODE_ID)
            self.assertEqual(result["authentication"], "node_token_v1")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertNotIn(self.issued["token"], raw)

    def test_foreign_and_forged_tokens_rejected_for_every_route(self):
        foreign = generate_node_credentials(OTHER_ID)["token"]
        same_id_forgery = generate_node_credentials(NODE_ID)["token"]
        for token in (None, foreign, same_id_forgery):
            for path in ("/v1/node", "/v1/domains", "/v1/domains/top", "/v1/domains/example.com/users", "/v1/users/u1/domains", "/v1/users/u1/domains/history", "/v1/users/u1/domains/top", "/v1/server", "/v1/server/jobs", "/v1/server/jobs/abc"):
                with self.assertRaises(HTTPError) as caught:
                    self.request(path, token)
                self.assertEqual(caught.exception.code, 401)
            with self.assertRaises(HTTPError) as caught:
                self.request("/v1/server/actions", token, b'{}')
            self.assertEqual(caught.exception.code, 401)

    def test_header_duplicates_and_query_tokens_are_rejected(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        connection.putrequest("GET", "/v1/node")
        for _ in range(2):
            connection.putheader("Authorization", "Bearer " + self.issued["token"])
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 401)
        response.read()
        connection.close()
        with self.assertRaises(HTTPError) as caught:
            self.request("/v1/node?token=" + self.issued["token"])
        self.assertEqual(caught.exception.code, 401)
        with self.assertRaises(HTTPError) as caught:
            self.request("/v1/node?anything=1", self.issued["token"])
        self.assertEqual(caught.exception.code, 400)
