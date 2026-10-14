from dataclasses import replace
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from remnawatch.api import dispatch, make_server
from remnawatch.collector import Tailer, NetworkSampler
from remnawatch.events import Event, AccessParser, UserMap, domain_name, correlated_metadata
from remnawatch.store import Store, Policy

NOW = 1791900000
USERS = [{"node_id": "n1", "inbound": "in", "email": "alice", "user_id": "u1"},
         {"node_id": "n2", "inbound": "in", "email": "alice", "user_id": "u2"}]
LINE = "2026/10/13 12:00:00 from 192.0.2.1:12345 accepted tcp:EXAMPLE.COM:443 [in -> out] email: alice\n"


def event(number=1, **changes):
    return replace(Event(str(number), "n1", "u1", NOW - 60, "example.com", None,
                         "192.0.2.1", "tcp", 443, "in", "out", "client_request", "observed"), **changes)


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.parser = AccessParser("n1", UserMap(USERS))

    def test_domain_validation(self):
        self.assertEqual(domain_name("Пример.РФ."), "xn--e1afmkfd.xn--p1ai")
        for value in ("https://example.com/a", "example.com/cookie", "*.example.com", "x@y.com", "192.0.2.1", "a..b", "-a.com", "x" * 64 + ".com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                domain_name(value)

    def test_access_origin_not_guessed(self):
        e = self.parser.parse(LINE, "1")
        self.assertEqual((e.user_id, e.domain, e.destination_ip, e.source, e.confidence),
                         ("u1", "example.com", None, "xray_access", "unknown"))
        self.assertIsNone(e.bytes_transferred)
        self.assertEqual(AccessParser("n1", UserMap(USERS), client_request_verified=True).parse(LINE, "1").source, "client_request")

    def test_user_mapping_is_node_and_inbound_scoped(self):
        self.assertEqual(AccessParser("n2", UserMap(USERS)).parse(LINE, "1").user_id, "u2")
        for line in (LINE.replace("email: alice", "email: unknown"), LINE.replace("[in -> out]", "[other -> out]"), LINE.replace(" email: alice", "")):
            self.assertIsNone(self.parser.parse(line, "1"))
        with self.assertRaises(ValueError):
            UserMap(USERS + [USERS[0]])

    def test_ipv6_udp_and_detours(self):
        for detour in ("->", ">>", "==>"):
            line = LINE.replace("192.0.2.1:12345", "udp:[2001:db8::1]:12345").replace("tcp:EXAMPLE.COM:443", "udp:[2001:db8::2]:53").replace("->", detour)
            e = self.parser.parse(line, "1")
            self.assertEqual((e.domain, e.destination_ip, e.client_ip, e.protocol, e.source),
                             (None, "2001:db8::2", "2001:db8::1", "udp", "ip_only"))

    def test_rejected_and_sensitive_input_not_stored(self):
        for line in (LINE.replace("accepted", "rejected"), LINE.replace("EXAMPLE.COM", "example.com/path"), LINE + "Cookie: secret", "x" * 9000):
            self.assertIsNone(self.parser.parse(line, "1"))

    def test_timezone(self):
        a = AccessParser("n1", UserMap(USERS), 420).parse(LINE, "1")
        b = self.parser.parse(LINE, "1")
        self.assertEqual(b.timestamp - a.timestamp, 7 * 3600)

    def test_metadata_requires_exact_correlation(self):
        data = {"connection_id": "c1", "node_id": "n1", "inbound": "in", "email": "alice",
                "timestamp": NOW - 1, "domain": "example.com", "protocol": "tcp", "destination_port": 443,
                "source": "tls_sni", "correlation_verified": True}
        self.assertEqual(correlated_metadata(data, UserMap(USERS)).source, "tls_sni")
        for changes in ({"correlation_verified": False}, {"email": "missing"}, {"cookies": "secret"}):
            with self.assertRaises(ValueError):
                correlated_metadata(data | changes, UserMap(USERS))


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.sqlite", clock=lambda: NOW)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def query(self, **kwargs):
        return self.store.query(**({"start": NOW - 3600, "end": NOW} | kwargs))

    def test_history_filter_pagination_and_top(self):
        self.store.ingest([event(1), event(2), event(3, user_id="u2", domain="other.com"),
                           event(4, timestamp=NOW, domain="outside.com")])
        result = self.query(user_id="u1", mode="history", limit=1, offset=1)
        self.assertEqual(result["total"], 2)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(self.query(mode="top")["items"][0]["connections"], 2)
        self.assertEqual(self.query(search="other")["items"][0]["domain"], "other.com")
        self.assertEqual(self.query(domain="example.com", mode="users")["items"][0]["user_id"], "u1")

    def test_dedup_and_atomic_checkpoint(self):
        self.assertEqual(self.store.ingest([event(1), event(1)], ("cursor", "100")), 1)
        self.assertEqual(self.query()["items"][0]["connections"], 1)
        self.assertEqual(self.store.state("cursor"), "100")
        with self.assertRaises(AttributeError):
            self.store.ingest([event(2), object()], ("cursor", "200"))
        self.assertEqual(self.store.state("cursor"), "100")
        self.assertEqual(self.query()["items"][0]["connections"], 1)

    def test_retention_and_disable(self):
        self.store.ingest([event(1, timestamp=NOW - 8 * 86400), event(2), event(3, timestamp=NOW - 31 * 86400)])
        self.assertEqual(self.query(start=NOW - 30 * 86400, mode="history")["total"], 1)
        self.assertEqual(self.query(start=NOW - 30 * 86400)["items"][0]["connections"], 2)
        self.store.set_enabled(False)
        self.assertEqual(self.query()["total"], 0)
        self.assertEqual(self.store.ingest([event(4)]), 0)
        self.assertFalse(self.query()["quality"]["collection_enabled"])

    def test_cleanup_and_dedup_outlive_details(self):
        self.store.ingest([event()])
        self.store.clock = lambda: NOW + 8 * 86400
        self.store.maintain()
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM events").fetchone()[0], 0)
        self.assertEqual(self.store.ingest([event()]), 0)
        self.store.clock = lambda: NOW + 31 * 86400
        self.store.maintain()
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM aggregates").fetchone()[0], 0)

    def test_unknown_domain_and_exact_traffic(self):
        self.store.ingest([event(1, domain=None, destination_ip="192.0.2.2", source="ip_only", confidence="unknown"),
                           event(2, bytes_transferred=123), event(3)])
        result = self.query()
        self.assertAlmostEqual(result["quality"]["domain_coverage"], 2 / 3)
        self.assertIsNone(result["items"][0]["bytes_transferred"])
        self.assertEqual(result["items"][0]["measured_connections"], 1)
        self.assertEqual(self.query(mode="top")["total"], 1)
        self.store.ingest([event(4, domain="measured.com", bytes_transferred=120),
                           event(5, domain="measured.com", bytes_transferred=80)])
        self.assertEqual(self.query(search="measured")["items"][0]["bytes_transferred"], 200)

    def test_activity_network_context(self):
        self.store.ingest([event()])
        self.store.network_sample("n1", NOW - 60, 1000)
        result = self.query(mode="activity", bucket="day")
        self.assertEqual(result["items"][0]["network_load"][0]["peak_bps"], 1000)
        self.assertIsNone(result["items"][0]["bytes_transferred"])

    def test_large_volume_is_batched_and_aggregated(self):
        for batch in range(30):
            self.store.ingest([event(batch * 1000 + n, user_id="u" + str(n % 10)) for n in range(1000)])
        self.assertEqual(self.query()["items"][0]["connections"], 30000)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM aggregates").fetchone()[0], 10)
        self.assertEqual(self.query(mode="history", limit=500, offset=29500)["total"], 30000)

    def test_tail_restart_partial_line_rotation_and_truncation(self):
        path = Path(self.temp.name) / "access.log"
        path.write_text(LINE, encoding="utf-8")
        parser = AccessParser("n1", UserMap(USERS))
        self.store.clock = lambda: parser.parse(LINE, "now").timestamp + 1
        tail = Tailer(path, parser, self.store, start_at_end=False)
        self.assertEqual(tail.poll(), 1)
        tail.close()
        tail = Tailer(path, parser, self.store, start_at_end=False)
        self.assertEqual(tail.poll(), 0)
        with path.open("a", encoding="utf-8") as log:
            log.write(LINE[:30])
        self.assertEqual(tail.poll(), 0)
        with path.open("a", encoding="utf-8") as log:
            log.write(LINE[30:])
        self.assertEqual(tail.poll(), 1)
        tail.close()
        path.rename(path.with_suffix(".old"))
        path.write_text(LINE, encoding="utf-8")
        tail = Tailer(path, parser, self.store)
        self.assertEqual(tail.poll(), 1)
        path.write_text(LINE.replace("EXAMPLE.COM", "other.example"), encoding="utf-8")
        self.assertEqual(tail.poll(), 1)
        tail.close()

    def test_api_routes_and_validation(self):
        self.store.ingest([event()])
        for path in ("/v1/domains", "/v1/domains/top", "/v1/domains/example.com/users", "/v1/users/u1/domains", "/v1/users/u1/domains/history", "/v1/users/u1/domains/top"):
            result = dispatch(self.store, path, {"period": ["5m"], "limit": ["1"], "offset": ["0"]})
            self.assertEqual(result["total"], 1)
        for q in ({"limit": ["501"]}, {"from": [str(NOW)]}, {"period": ["5m", "1h"]}, {"from": ["2026-10-13T00:00:00"], "to": [str(NOW)]}, {"period": ["5m"], "from": ["1"], "to": ["2"]}):
            with self.assertRaises(ValueError):
                dispatch(self.store, "/v1/domains", q)

    def test_disabled_collector_skips_without_backfill(self):
        path = Path(self.temp.name) / "disabled.log"
        path.write_text(LINE, encoding="utf-8")
        parser = AccessParser("n1", UserMap(USERS))
        self.store.clock = lambda: parser.parse(LINE, "now").timestamp + 1
        tail = Tailer(path, parser, self.store, start_at_end=False)
        self.store.set_enabled(False)
        self.assertEqual(tail.poll(), 0)
        self.store.set_enabled(True)
        self.assertEqual(tail.poll(), 0)
        with path.open("a", encoding="utf-8") as log:
            log.write(LINE)
        self.assertEqual(tail.poll(), 1)
        tail.close()

    def test_oversized_line_suffix_never_becomes_event_after_restart(self):
        path = Path(self.temp.name) / "large.log"
        path.write_bytes(b"x" * 16386 + LINE.encode() + LINE.encode())
        parser = AccessParser("n1", UserMap(USERS))
        self.store.clock = lambda: parser.parse(LINE, "now").timestamp + 1
        tail = Tailer(path, parser, self.store, start_at_end=False, batch_lines=1)
        self.assertEqual(tail.poll(), 0)
        tail.close()
        tail = Tailer(path, parser, self.store, start_at_end=False, batch_lines=1)
        self.assertEqual(tail.poll(), 0)
        self.assertEqual(tail.poll(), 0)  # Looks like a log line, but is a suffix.
        self.assertEqual(tail.poll(), 1)
        tail.close()

    def test_arbitrary_second_boundaries_and_current_retention_cutoff(self):
        self.store.ingest([event(1, timestamp=NOW - 61), event(2, timestamp=NOW - 60), event(3, timestamp=NOW - 59)])
        self.assertEqual(self.query(start=NOW - 60, end=NOW - 59)["items"][0]["connections"], 1)
        self.store.clock = lambda: NOW + 31 * 86400
        result = self.query()
        self.assertEqual(result["total"], 0)
        self.assertTrue(result["quality"]["period_truncated"])

    def test_http_authorization_all_routes(self):
        token = "a" * 32
        server = make_server(self.store, token, ("127.0.0.1", 0))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            for path in ("/v1/domains", "/v1/domains/top", "/v1/domains/example.com/users", "/v1/users/u1/domains", "/v1/users/u1/domains/history", "/v1/users/u1/domains/top"):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(base + path)
                self.assertEqual(caught.exception.code, 401)
                with urlopen(Request(base + path, headers={"Authorization": "Bearer " + token})) as response:
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertIn("quality", json.load(response))
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_network_sampler(self):
        path = Path(self.temp.name) / "netdev"
        path.write_text("eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n")
        sampler = NetworkSampler(self.store, "n1", ["eth0"], str(path))
        sampler.sample()
        path.write_text("eth0: 200 0 0 0 0 0 0 0 400 0 0 0 0 0 0 0\n")
        sampler.sample()
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM network").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
