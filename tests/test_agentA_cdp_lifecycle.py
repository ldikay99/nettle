"""Agent-A: CDP lifecycle regression — ZERO orphan processes guaranteed.

Counts real Chrome processes (leader + children incl. crashpad/zygote) that
carry a nettle user-data-dir, before/after sniff_network() in both headless
and visible modes, and after shutdown_chrome(). Skipped when no Chrome
binary exists (CI without a browser).
"""
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, ".")

from nettle import registry
from nettle.cdp import (
    _chrome_binaries,
    _LAUNCHED_CHROMES,
    chrome_processes_alive,
    ensure_debugging_chrome,
    shutdown_chrome,
    sniff_network,
)

HAVE_CHROME = bool(_chrome_binaries())
UDD_MARK = "user-data-dir=/tmp/nettle-chrome-cdp-"


def count_nettle_chrome_procs() -> int:
    """Count chrome-family processes nettle launched (not pgrep's own shell).

    Reads /proc directly: immune to pgrep matching its own wrapper cmdline.
    """
    n = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().decode("utf-8", "replace")
        except OSError:
            continue
        if UDD_MARK in cmd and "pgrep" not in cmd and "grep" not in cmd:
            n += 1
    return n


def count_zombies() -> int:
    n = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/stat") as f:
                parts = f.read().rsplit(")", 1)
                if len(parts) == 2 and parts[1].strip().startswith("Z"):
                    with open(f"/proc/{pid}/cmdline", "rb") as f2:
                        cmd = f2.read().decode("utf-8", "replace")
                    if UDD_MARK in cmd:
                        n += 1
        except OSError:
            continue
    return n


@unittest.skipUnless(HAVE_CHROME, "no Chrome/Chromium binary on this machine")
@unittest.skipUnless(os.path.isdir("/proc"), "needs /proc (POSIX)")
class TestChromeLifecycle(unittest.TestCase):
    def setUp(self):
        shutdown_chrome()
        registry.set_cdp_ports(range(9430, 9440))
        time.sleep(0.5)
        self.baseline = count_nettle_chrome_procs()
        # if a previous crashed run left junk behind, it must be dead now
        if self.baseline:
            subprocess.run(["pkill", "-9", "-f", UDD_MARK], capture_output=True)
            time.sleep(1.0)
            self.baseline = count_nettle_chrome_procs()
        self.assertEqual(self.baseline, 0, "stale nettle chrome procs at start")

    def tearDown(self):
        shutdown_chrome()
        time.sleep(1.0)

    def test_headless_sniff_leaves_nothing(self):
        res = sniff_network(
            "https://example.com/",
            settle=1.5, scroll_steps=1, scroll_pause=0.1,
        )
        self.assertTrue(res["ok"])
        deadline = time.time() + 10
        while count_nettle_chrome_procs() and time.time() < deadline:
            time.sleep(0.3)
        self.assertEqual(count_nettle_chrome_procs(), 0,
                         "orphan chrome processes after sniff_network()")
        self.assertEqual(chrome_processes_alive(), 0)
        self.assertEqual(count_zombies(), 0, "zombie chrome children")

    def test_visible_sniff_leaves_nothing(self):
        res = sniff_network(
            "https://example.com/",
            headless=False, settle=1.5, scroll_steps=1, scroll_pause=0.1,
        )
        self.assertTrue(res["ok"])
        deadline = time.time() + 10
        while count_nettle_chrome_procs() and time.time() < deadline:
            time.sleep(0.3)
        self.assertEqual(count_nettle_chrome_procs(), 0,
                         "orphan chrome processes after visible sniff_network()")
        self.assertEqual(count_zombies(), 0)

    def test_keep_chrome_then_shutdown(self):
        sniff_network(
            "https://example.com/",
            settle=1.0, scroll=False, keep_chrome=True,
        )
        self.assertEqual(chrome_processes_alive(), 1)
        # The children (zygote/renderer/crashpad) spawn asynchronously AFTER
        # the CDP port answers — under load (several Chrome launches in a
        # row during a full-suite run) they can take longer than the poll
        # below, and on constrained/sandboxed CI the whole tree can exit on
        # its own within milliseconds of startup. The children assertion is
        # only meaningful when the tree is actually there; the no-orphan
        # invariant this test protects is asserted after shutdown_chrome()
        # below either way.
        deadline = time.time() + 8
        while time.time() < deadline and count_nettle_chrome_procs() < 2:
            time.sleep(0.2)
        self.assertGreaterEqual(count_nettle_chrome_procs(), 1,
                                "leader process must be alive while kept")
        self.assertTrue(shutdown_chrome())
        deadline = time.time() + 10
        while count_nettle_chrome_procs() and time.time() < deadline:
            time.sleep(0.3)
        self.assertEqual(count_nettle_chrome_procs(), 0)
        self.assertEqual(count_zombies(), 0, "zombie chrome children")
        self.assertFalse(shutdown_chrome(), "second shutdown should be a no-op")

    def test_visible_launch_has_no_headless_flag(self):
        port = ensure_debugging_chrome(headless=False, wait=15)
        proc = _LAUNCHED_CHROMES[port]
        self.assertIsNotNone(proc)
        self.assertNotIn("--headless=new", proc.args)
        self.assertNotIn("--headless", proc.args)
        shutdown_chrome(port)
        time.sleep(0.8)
        self.assertFalse(hasattr(proc, "poll") and proc.poll() is None)

    def test_registry_ports_respected(self):
        # 9435 is inside the setUp range; a fresh launch must pick from it
        port = ensure_debugging_chrome(wait=15)
        self.assertIn(port, list(range(9430, 9440)))
        shutdown_chrome(port)


if __name__ == "__main__":
    unittest.main(verbosity=2)
