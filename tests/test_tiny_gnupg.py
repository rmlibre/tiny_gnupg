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
from time import sleep
from pathlib import Path
from aiohttp import ClientSession
from aiohttp_socks import SocksConnector
from multiprocessing import Process

PACKAGE_PATH = str(Path(__file__).parent.parent)
sys.path.append(PACKAGE_PATH)
run = asyncio.get_event_loop().run_until_complete

from tiny_gnupg import GnuPG


@pytest.fixture(scope="module")
def gpg():
    print("setup".center(15, "-"))
    username = "testing_user"
    email = "testing_user@testing.testing"
    passphrase = "test_passphrase"
    relative_gpg_path = PACKAGE_PATH + "/tiny_gnupg/gpghome"
    gpg = GnuPG(username, email, passphrase)
    gpg.set_homedir(relative_gpg_path)
    gpg.reset_daemon()
    sleep(0.2)
    yield gpg
    print("teardown".center(18, "-"))


def test_instance(gpg):
    gpg.gen_key()
    assert gpg.username == "testing_user"
    assert gpg.email == "testing_user@testing.testing"
    assert gpg.fingerprint == "" or type(gpg.fingerprint) == str
    assert gpg.passphrase == "test_passphrase"
    assert gpg.home.endswith("gpghome")
    assert gpg.executable.endswith("gpg2")
    assert gpg._connector == SocksConnector
    assert gpg._session == ClientSession
    assert gpg.port == 80
    assert gpg.tor_port == 9050
    assert ".onion" in gpg.keyserver
    assert ".onion" in gpg.searchserver
    assert gpg.fingerprint in gpg.list_keys()


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


def test_cipher(gpg):
    message = "\n  twenty\ntwo\narmed\ndogs\nrush\nthe\nkibble  \n\n"
    encrypted_message_0 = gpg.encrypt(
        message=message,
        uid=gpg.fingerprint,
        local_user=gpg.fingerprint,
    )
    encrypted_message_1 = gpg.encrypt(
        message=message,
        uid=gpg.fingerprint,
    )
    encrypted_message_2 = gpg.encrypt(
        message=message,
        uid=gpg.fingerprint,
        local_user=gpg.fingerprint,
        sign=False,
    )
    encrypted_message_3 = gpg.encrypt(
        message=message,
        uid=gpg.fingerprint,
        sign=False,
    )
    assert gpg.decrypt(encrypted_message_0) == message + "\n"
    assert gpg.decrypt(encrypted_message_1) == message + "\n"
    assert gpg.decrypt(encrypted_message_2) == message + "\n"
    assert gpg.decrypt(encrypted_message_3) == message + "\n"


def test_file_io(gpg):
    path = gpg.home
    file_path = f"{path}/{gpg.fingerprint}.asc"
    key = gpg.text_export(gpg.fingerprint)
    run(gpg.file_export(path, gpg.fingerprint))
    run(gpg.file_import(file_path))
    Path(file_path).unlink()


def test_networking(gpg):
    dev_email = "gonzo.development@protonmail.ch"
    dev_fingerprint = "31FDCC4F9961AFAC522A9D41AE2B47FA1EF44F0A"
    key_url = run(gpg.search(dev_email))
    assert "\n" not in key_url
    assert " " not in key_url
    assert "<" not in key_url
    assert ">" not in key_url
    key = run(gpg.get(key_url))
    gpg.text_import(key)
    assert gpg.list_keys(dev_email)
    fingerprint = gpg.key_fingerprint(dev_email)
    assert dev_fingerprint == fingerprint
    assert fingerprint == next(iter(gpg.list_keys(dev_fingerprint)))
    email = gpg.key_email(fingerprint)
    assert dev_email == email
    assert email == gpg.list_keys(dev_email)[fingerprint]
    key_from_email = gpg.text_export(email)
    key_from_fingerprint = gpg.text_export(fingerprint)
    assert key_from_email == key_from_fingerprint
    gpg.text_import(key_from_email)
    run(gpg.network_import(dev_email))
    try:
        assert key == key_from_email
    except:
        pass  # removed and/or reencoded uids
    finally:
        assert len(gpg.list_keys(dev_email)) == 1
    run(gpg.network_export(gpg.fingerprint))
    test_key_url = run(gpg.search(gpg.fingerprint))
    local_key = gpg.text_export(gpg.fingerprint)
    network_key = run(gpg.get(test_key_url))
    assert local_key != network_key  # removed and/or reencoded uids
    try:
        gpg.text_import(network_key)
        failed = False
    except:
        failed = True  # GnuPG bug #T4393
    finally:
        assert failed
    try:
        run(gpg.network_import(gpg.fingerprint))
        failed = False
    except:
        failed = True  # GnuPG bug #T4393
    finally:
        assert failed
    # The key returned by the keyserver can have different bits due to
    # different versions of encoding of header information on the key.
    # The folks over at keys.openpgp.org were able to deduce the issue
    # after we sent them a bug report. GnuPG currently has "newer" and
    # "older" style header formatting, which leads to inconsistent
    # results when handling newer ECC keys.


def test_delete(gpg):
    email = "testing_user@testing.testing"
    amount_of_test_keys = 0
    for key_email in gpg.list_keys().values():
        if key_email == email:
            amount_of_test_keys += 1
    gpg.delete(email)
    amount_of_test_keys_after_delete = 0
    for key_email in gpg.list_keys().values():
        if key_email == email:
            amount_of_test_keys_after_delete += 1
    assert amount_of_test_keys - 1 == amount_of_test_keys_after_delete
