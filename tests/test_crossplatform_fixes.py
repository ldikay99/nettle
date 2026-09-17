"""Cross-platform + controlled-error regression tests."""

import json as _json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, ".")

from nettle import exceptions, filter_urls, request
from nettle.cdp import _chrome_binaries, _close_tab_quietly
from nettle.format import write_json, write_csv
from nettle.network import probe_apis
from nettle.http import Response


def _resp(body: bytes, ctype="text/html"):
    return Response(
        url="https://x.example/", status=200, headers={"Content-Type": ctype},
        body=body, method="GET",
    )


class TestChromeDiscovery(unittest.TestCase):
    def test_env_override(self):
        old = os.environ.get("NETTLE_CHROME_BIN")
        fake = tempfile.NamedTemporaryFile(suffix=".sh", delete=False)
        fake.write(b"#!/bin/sh\n"); fake.close()
        try:
            os.environ["NETTLE_CHROME_BIN"] = fake.name
            bins = _chrome_binaries()
            self.assertEqual(bins[0], fake.name)
        finally:
            if old is None:
                os.environ.pop("NETTLE_CHROME_BIN", None)
            else:
                os.environ["NETTLE_CHROME_BIN"] = old
            os.unlink(fake.name)

    def test_close_tab_quietly_safe(self):
        _close_tab_quietly(9222, None)      # no id → no-op
        _close_tab_quietly(9222, "zzz")     # no browser → swallowed


class TestControlledErrors(unittest.TestCase):
    def test_json_error_is_nettle_and_value_error(self):
        r = _resp(b"<html>not json</html>")
        with self.assertRaises(exceptions.JsonBodyError):
            r.json()
        try:
            r.json()
        except exceptions.NettleError:
            pass  # NettleError hierarchy works
        except ValueError:
            self.fail("should be catchable via NettleError")
        try:
            r.json()
        except ValueError:
            pass  # ValueError compat works
        except Exception:
            self.fail("should be catchable via ValueError")

    def test_valid_json_still_works(self):
        r = _resp(b'{"ok": true}', ctype="application/json")
        self.assertEqual(r.json(), {"ok": True})

    def test_bad_regex_raises_selector_error(self):
        with self.assertRaises(exceptions.SelectorError):
            filter_urls(["https://x.com/a"], pattern="([unclosed")

    def test_probe_missing_url_clear_error(self):
        with self.assertRaises(ValueError) as cm:
            probe_apis([{"method": "GET"}])
        self.assertIn("url", str(cm.exception))

    def test_malformed_url_raises_fetch_error(self):
        for bad in ("notaurl", "ftp://???", "http://[::1:bad"):
            with self.assertRaises(exceptions.FetchError):
                request("GET", bad, retries=0, timeout=3)


class TestFileWrites(unittest.TestCase):
    def test_write_json_unicode_roundtrip(self):
        data = {"título": "café — ñoño", "tags": ["\u00a0", "x"]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.json")
            write_json(p, data)
            with open(p, encoding="utf-8") as f:
                back = _json.load(f)
        self.assertEqual(back["título"], data["título"])

    def test_write_csv_unicode(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "out.csv")
            write_csv(p, [{"nombre": "Ñu"}])
            with open(p, encoding="utf-8") as f:
                content = f.read()
        self.assertIn("Ñu", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
