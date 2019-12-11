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
import asyncio
import pathlib
from shlex import quote
from aiohttp import ClientSession
from aiohttp_socks import SocksConnector
from multiprocessing import Process

sys.path.append(os.getcwd() + "/../")
run = asyncio.get_event_loop().run_until_complete

from tiny_gnupg import GnuPG


@pytest.fixture(scope="module")
def gpg():
    print("setup".center(15, "-"))
    username = "testing_user"
    email = "testing_user@testing.org"
    passphrase = "test_passphrase"
    relative_gpg_path = "../tiny_gnupg/gpghome"
    gpg = GnuPG(username, email, passphrase)
    gpg.set_homedir(relative_gpg_path)
    yield gpg
    print("teardown".center(18, "-"))


async def fetch(gpg, url):
    async with gpg.network_get(url) as response:
        return await response.text()


def test_networking(gpg):
    dev_email = "gonzo.development@protonmail.ch"
    key_url = run(gpg.search(dev_email))
    assert "\n" not in key_url
    assert " " not in key_url
    assert "<" not in key_url
    assert ">" not in key_url
    key = run(fetch(gpg, key_url))
    gpg.text_import(key)
    fingerprint = gpg.key_fingerprint(dev_email)
    email = gpg.key_email(fingerprint)
    assert dev_email == email
    assert email == gpg.list_keys(dev_email)[fingerprint]
    key_from_email = gpg.text_export(email)
    key_from_fingerprint = gpg.text_export(fingerprint)
    assert key_from_email == key_from_fingerprint
    # For some reason, the key returned by the key server has
    # different bits, they're changed around from thos that are
    # uploaded. This seems like a bug, and which bit are being changed
    # is an open question at the moment. It most probably has to do
    # with the fact that they remove user id information until an
    # email address is confirmed, and they process of reattaching the
    # user id information is buggy or undeterministic.


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
        command.remove(option)
        assert command == gpg.command()
        passphrase_command.remove(option)
        assert passphrase_command == gpg.command(with_passphrase=True)

