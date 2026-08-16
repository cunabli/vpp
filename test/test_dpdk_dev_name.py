#!/usr/bin/env python3
"""Board-free reachability test for the dpdk `dev <bus>:<name> { ... }` grammar.

The dpdk startup config gained a per-device stanza keyed by bus name, e.g.

    dpdk { dev fslmc:dpni.7 { name WAN } }

so an fslmc device (which has no PCI address) can be named and tuned by its
bus name. This test only proves that a real VPP *parses and dispatches* the
new grammar: it boots VPP with the stanza and runs the plugin's in-process C
gate. CI has no fslmc device, so it asserts nothing about whether a rename or
ring-size actually took effect on hardware -- only that the parser accepts the
grammar and dpdk_device_config() keys/validates it. Hardware behaviour is
covered on the board, not here.
"""

import os
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from config import config

DPDK_PLUGIN = "dpdk_plugin.so"


def dpdk_plugin_available():
    """True if dpdk_plugin.so is present in the configured plugin path.

    The test framework builds without a guaranteed dpdk plugin, so skip
    cleanly rather than erroring when it is absent.
    """
    return any(
        os.path.isfile(os.path.join(d, DPDK_PLUGIN)) for d in config.vpp_plugin_dir
    )


class DpdkDevNameTestCase(VppTestCase):
    """Reachability of the dpdk `dev <bus>:<name>` grammar (parse/dispatch only).

    Scope caveat: CI has no fslmc device. This asserts that VPP parses the new
    grammar and that dpdk_device_config() accepts it (via the plugin's C gate);
    it does NOT assert any rename or ring-size took effect on a device.
    """

    # A single named fslmc device -- mirrors how the parser keys by bus name.
    extra_vpp_config = ["dpdk { dev fslmc:dpni.7 { name WAN } }"]

    @classmethod
    def setUpConstants(cls):
        super(DpdkDevNameTestCase, cls).setUpConstants()
        # The framework disables dpdk_plugin.so by default, and re-declaring the
        # plugin collides ("plugin already configured"). Flip the existing token
        # so the dpdk config handler and the `test dpdk dev-config` CLI load.
        cmd = cls.vpp_cmdline
        i = cmd.index(DPDK_PLUGIN)
        cmd[cmd.index("disable", i)] = "enable"

    @classmethod
    def setUpClass(cls):
        # Guard here, not on the test method: super().setUpClass() boots VPP with
        # the dpdk stanza, so on a build without dpdk_plugin.so a method-level
        # skip would still let the boot fail with a class-level VppDiedError.
        if not dpdk_plugin_available():
            raise unittest.SkipTest("dpdk_plugin.so not available")
        super(DpdkDevNameTestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(DpdkDevNameTestCase, cls).tearDownClass()

    def test_dev_name_grammar_reachable(self):
        """dpdk dev <bus>:<name> grammar parses and the C gate passes"""
        # Reaching here means VPP booted with the `dev fslmc:dpni.7 { name WAN }`
        # stanza, i.e. the parser accepted the new grammar and dispatched it.
        # In-process C gate: drives dpdk_device_config() and asserts NAME keying,
        # options, duplicate-key rejection and PCI-still-parses invariants.
        out = self.vapi.cli("test dpdk dev-config")
        self.assertIn("PASS", out)
        # Note: the duplicate-key rejection is asserted inside that C gate (it
        # only prints PASS if dpdk_device_config() errored on a repeated key).
        # Asserting a real VPP *boot* fails on a duplicate block is not attempted
        # here: a failed boot raises VppDiedError out of setUpClass for the whole
        # class, which VppTestCase cannot turn into an expected-failure assertion.


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
