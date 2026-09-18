"""Agent A round 3 — pure-Python brotli decoder (item 3).

Vectors in tests/fixtures/brotli_vectors.json were generated ONCE with the
pip `brotli` package (qualities 0-11 + a streaming multi-meta-block case +
real multilingual HTML fixtures). The decoder under test is nettle's own
pure-Python implementation — the pip package is NOT needed to run this.
"""
import base64
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from nettle.brotli_dec import (  # noqa: E402
    BrotliError,
    _split_cmd,
    decompress,
)
from nettle import _brotli_data as data  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


class TestBrotliDataIntegrity(unittest.TestCase):
    def test_dictionary_size(self):
        self.assertEqual(len(data.DICT), 122784)  # RFC 7932 Appendix A

    def test_dictionary_offsets_consistent(self):
        off = data.OFFSETS
        bits = data.SIZE_BITS
        for ln in range(4, 24):
            n = off[ln] + ln * (1 << bits[ln])
            self.assertEqual(n, off[ln + 1], f"length {ln} region")
        self.assertEqual(off[24] + 24 * (1 << bits[24]), 122784)

    def test_transforms(self):
        self.assertEqual(len(data.TRANSFORMS), 121)
        self.assertEqual(data.TRANSFORMS[0], (49, 0, 49))  # identity / empty
        self.assertTrue(all(0 <= t[1] <= 20 for t in data.TRANSFORMS))


class TestCommandTable(unittest.TestCase):
    """The 704-symbol insert&copy table must split exactly per RFC Section 5
    (verified against the reference kCmdLut during development)."""

    def test_dist_zero_ranges(self):
        for cmd in range(0, 128):
            _, _, dz = _split_cmd(cmd)
            self.assertTrue(dz, cmd)
        for cmd in range(128, 704):
            _, _, dz = _split_cmd(cmd)
            self.assertFalse(dz, cmd)

    def test_cell_boundaries(self):
        # 384..447: insert 0..7 with copy 16..23
        self.assertEqual(_split_cmd(384), (0, 16, False))
        self.assertEqual(_split_cmd(447), (7, 23, False))
        # 640..703: insert 16..23 with copy 16..23
        self.assertEqual(_split_cmd(640), (16, 16, False))
        self.assertEqual(_split_cmd(703), (23, 23, False))
        # 0..63: insert 0..7 copy 0..7 dist0
        self.assertEqual(_split_cmd(0), (0, 0, True))
        self.assertEqual(_split_cmd(63), (7, 7, True))

    def test_out_of_range(self):
        with self.assertRaises(BrotliError):
            _split_cmd(704)


class TestDecompressVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIX, "brotli_vectors.json")) as f:
            cls.vectors = json.load(f)
        with open(os.path.join(FIX, "brotli_digests.json")) as f:
            cls.digests = json.load(f)

    def test_all_vectors_match_reference(self):
        from nettle.http import _decode_body
        checked = 0
        for v in self.vectors:
            comp = base64.b64decode(v["b64"])
            out = decompress(comp)
            self.assertEqual(len(out), v["raw_len"], f"{v['name']} q{v['q']}")
            digest = hashlib.sha256(out).hexdigest()
            self.assertEqual(
                digest, self.digests[v["name"]],
                f"{v['name']} q{v['q']} decoded wrong content",
            )
            # same stream through the HTTP body decoder
            self.assertEqual(_decode_body(comp, "br"), out)
            checked += 1
        self.assertGreaterEqual(checked, 50)

    def test_streaming_multiblock(self):
        v = next(x for x in self.vectors if x["name"] == "stream3")
        out = decompress(base64.b64decode(v["b64"]))
        self.assertEqual(out, b"A" * 5000 + b"B" * 5000 + b"C" * 5000)

    def test_english_uses_static_dictionary(self):
        # q11 on English text exercises dictionary references + transforms;
        # we verify the transform engine produced correct bytes via digest.
        v = next(x for x in self.vectors if x["name"] == "english" and x["q"] == 11)
        out = decompress(base64.b64decode(v["b64"]))
        self.assertIn(b"that you", out)
        self.assertEqual(hashlib.sha256(out).hexdigest(), self.digests["english"])


class TestDecompressErrors(unittest.TestCase):
    def test_empty(self):
        with self.assertRaises(BrotliError):
            decompress(b"")

    def test_garbage_never_hangs_or_crashes(self):
        # garbage must either raise BrotliError or produce SOMETHING — but
        # never hang, crash with a weird exception, or loop forever.
        import signal

        def _timeout(signum, frame):  # pragma: no cover
            raise TimeoutError("decoder hung")

        old = signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(10)
        try:
            for junk in (b"\xff" * 20, b"\x00" * 10, b"\x00" * 64, os.urandom(64),
                         b"\x8b\x00" + os.urandom(30)):
                try:
                    decompress(junk)  # may or may not error — both acceptable
                except BrotliError:
                    pass
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)

    def test_truncated(self):
        v = next(x for x in json.load(open(os.path.join(FIX, "brotli_vectors.json")))
                 if x["name"] == "code" and x["q"] == 9)
        comp = base64.b64decode(v["b64"])
        with self.assertRaises((BrotliError, IndexError)):
            decompress(comp[: len(comp) // 2])

    def test_type_check(self):
        with self.assertRaises(TypeError):
            decompress("not bytes")  # type: ignore[arg-type]


class TestBrotliHttpIntegration(unittest.TestCase):
    """brotli path through the Session/Response plumbing."""

    def test_decode_body_stacked(self):
        import gzip as _gzip
        from nettle.http import _decode_body
        v = next(x for x in json.load(open(os.path.join(FIX, "brotli_vectors.json")))
                 if x["name"] == "greet" and x["q"] == 5)
        br = base64.b64decode(v["b64"])
        # br applied first, gzip applied on top -> header "br, gzip"
        # (decode peels layers right-to-left)
        gz = _gzip.compress(br)
        self.assertEqual(_decode_body(gz, "br, gzip"), decompress(br))

    def test_session_advertises_br_and_registry_controls_it(self):
        import nettle
        try:
            s = nettle.Session()
            self.assertIn("br", s.headers["Accept-Encoding"])
            nettle.registry.http["accept_encoding"] = "gzip, deflate"
            s2 = nettle.Session()
            self.assertNotIn("br", s2.headers["Accept-Encoding"])
        finally:
            nettle.registry.http["accept_encoding"] = "gzip, deflate, br"


if __name__ == "__main__":
    unittest.main(verbosity=2)
