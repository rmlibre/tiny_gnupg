# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#

import os
import sys
import pytest
import pathlib
from aiohttp import ClientSession
from aiohttp_socks import SocksConnector

sys.path.append(os.getcwd() + "/../")

from tiny_gnupg import GnuPG


username = "testing_user"
email = "testing.user@tests.net"
passphrase = "test_passphrase"
relative_gpg_path = "../tiny_gnupg/gpghome/gpg2"


@pytest.fixture(scope="module")
def gpg():
    print("setup".center(15, "-"))
    gpg = GnuPG(username, email, passphrase)
    gpg.path = gpg.format_homedir(relative_gpg_path)
    yield gpg
    print("teardown".center(18, "-"))


def test_instance(gpg):
    assert gpg.username
    assert "@" in gpg.email
    assert gpg.fingerprint == "" or type(gpg.fingerprint) == str
    assert gpg.passphrase
    assert gpg.home.endswith("gpghome")
    assert gpg.executable.endswith("gpg2")
    assert gpg._connector == SocksConnector
    assert gpg._session == ClientSession
    assert gpg.port == 80
    assert gpg.tor_port == 9050
    assert ".onion" in gpg.keyserver
    assert ".onion" in gpg.searchserver


def test_encode_inputs(gpg):
    inputs = ["1", "y", "q"]
    mock_encoded_inputs = ["1", "\n", "y", "\n", "q", "\n"]
    encoded_inputs = gpg.encode_inputs(*inputs)
    assert type(encoded_inputs) == bytes
    assert encoded_inputs.endswith(b"\n")
    for element in inputs:
        assert bytes(element, "utf-8") in encoded_inputs
    for index, element in enumerate(mock_encoded_inputs):
        assert bytes(element, "utf-8")[0] == encoded_inputs[index]


def test_command(gpg):
    options = ["--list-keys"]
    command = gpg.command(*options)
    passphrase_command = gpg.command(*options, with_passphrase=True)
    for option in options:
        assert option in command
        assert option in passphrase_command
