# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


"""
To test tiny_gnupg.py, there SHOULD NOT be a system installation of
tiny_gnupg. Otherwise this import statement for the module will call the
system for the package information stored there. But the keyrings are
different, so this will lead to crashes and failing test cases.

A workaround, if a system installation is desired or can't be deleted,
is to move this test close to the system script. One directory up, and
into a tests folder. This is less desirable if sudo was used to install
tiny_gnupg instead of the --user flag.
"""


import sys
import pytest
import asyncio
from pathlib import Path
from aiohttp import ClientSession
from aiohttp_socks import SocksConnector

PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)
new_task = asyncio.get_event_loop().create_task

from tiny_gnupg import GnuPG, run

dev_signed_message = """-----BEGIN PGP MESSAGE-----

owGbwMvMwCG2Ttv9l9wXfy7G08JJDLE/FmqVpBaXKOSmFhcnpqdydZSyMIhxMMiK
KbIY/j3jPzNx/ZogrbmOME2sTCAdDFycAjARoUKG/zHTV94+3btJc3XDD3nR3df4
p0iGPLWJkdRac/B7zMIH9/UYGb5uduZu5Xe5LNCwWcmRfUNiyV+97vbinoUxh2un
MDAbsAEA
=rP7l
-----END PGP MESSAGE-----
"""


@pytest.fixture(scope="module")
def gpg():
    print("setup".center(15, "-"))
    username = "testing_user"
    email = "testing_user@testing.testing"
    passphrase = "test_passphrase"
    relative_gpg_path = str(Path(PACKAGE_PATH).absolute() / "tiny_gnupg/gpghome")
    gpg = GnuPG(username, email, passphrase)
    gpg.set_homedir(relative_gpg_path)
    yield gpg
    print("teardown".center(18, "-"))


def test_instance(gpg):
    gpg.gen_key()
    test_gpg = GnuPG(gpg.username, gpg.email, gpg.passphrase)
    assert gpg.username == test_gpg.username
    assert gpg.email == test_gpg.email
    assert gpg.passphrase == test_gpg.passphrase
    assert gpg.port == test_gpg.port
    assert gpg.tor_port == test_gpg.tor_port
    assert gpg.home == test_gpg.home
    assert gpg.executable == test_gpg.executable
    assert gpg._connector == test_gpg._connector
    assert gpg._session == test_gpg._session
    assert gpg._search_string == test_gpg._search_string
    assert gpg.keyserver == test_gpg.keyserver
    assert str(gpg.port) in gpg.keyserver
    assert gpg.keyserver_export_api == test_gpg.keyserver_export_api
    assert gpg.keyserver_verify_api == test_gpg.keyserver_verify_api
    assert gpg.searchserver == test_gpg.searchserver
    assert gpg.base_command == test_gpg.base_command
    assert gpg.base_passphrase_command == test_gpg.base_passphrase_command
    ###
    assert gpg.username == "testing_user"
    assert gpg.email == "testing_user@testing.testing"
    assert len(gpg.fingerprint) == 40
    assert type(gpg.fingerprint) == str
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
    test_email = "support@keys.openpgp.org"
    run(gpg.network_import(test_email))
    message = "\n  twenty\ntwo\narmed\ndogs\nrush\nthe\nkibble  \n\n"
    for trust_level in range(1, 6):
        for fingerprint in gpg.list_keys():
            gpg.trust(fingerprint, trust_level)
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
        nonstandard_encrypted_message_0 = gpg.encrypt(
            message=message,
            uid=test_email,
        )
        nonstandard_encrypted_message_1 = gpg.encrypt(
            message=message,
            uid=test_email,
            sign=False
        )
        assert gpg.decrypt(encrypted_message_0) == message
        assert gpg.decrypt(encrypted_message_1) == message
        assert gpg.decrypt(encrypted_message_2) == message
        assert gpg.decrypt(encrypted_message_3) == message
        signed_message_0 = gpg.sign(message)
        signed_message_1 = gpg.sign(signed_message_0)
        signed_message_2 = gpg.sign(signed_message_1)
        signed_message_3 = gpg.sign(signed_message_2)
        signed_message_3 = gpg.sign(signed_message_3)
        gpg.verify(signed_message_0)
        gpg.verify(signed_message_1)
        gpg.verify(signed_message_2)
        gpg.verify(signed_message_3)
    gpg.delete(test_email)


def test_file_io(gpg):
    path = Path(gpg.home).absolute()
    file_path = str(path / f"{gpg.fingerprint}.asc")
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


def test_network_concurrency(gpg):
    async def gather_looper(gpg, uid):
        tasks = await looper(gpg, uid)
        return await asyncio.gather(*tasks)

    async def looper(gpg, uid):
        tasks = []
        for i in range(4):
            tasks.append(new_task(gpg.search(uid)))
        return tasks

    uid = "support@keys.openpgp.org"
    url = run(gpg.search(uid))
    urls = run(gather_looper(gpg, uid))
    assert url.strip()
    for link in urls:
        assert url == link
    urls = run(gather_looper(gpg, uid))
    for link in urls:
        assert url == link


def test_key_signing(gpg):
    dev_email = "gonzo.development@protonmail.ch"
    dev_fingerprint = "31FDCC4F9961AFAC522A9D41AE2B47FA1EF44F0A"
    command = gpg.command("--check-sigs")
    keyring = gpg.read_output(command)
    gpg.sign(dev_fingerprint, key=True)
    signed_keying = gpg.read_output(command)
    assert keyring != signed_keying
    condensed_keyring = signed_keying.replace(" ", "")
    fingerprint = gpg.fingerprint[-16:]
    assert f"<{dev_email}>\nsig!0x{fingerprint}" in condensed_keyring


def test_packet_parsing(gpg):
    signature = gpg.sign("test")
    signed_encrypted_message = gpg.encrypt("test", gpg.fingerprint)
    encrypted_message = gpg.encrypt("test", gpg.fingerprint, sign=False)
    gpg_key = gpg.text_export(gpg.fingerprint)
    ###
    signature_fingerprint = gpg.packet_fingerprint(signature)
    signed_encrypted_message_fingerprint = gpg.packet_fingerprint(
        signed_encrypted_message
    )
    encrypted_message_fingerprint = gpg.packet_fingerprint(
        encrypted_message
    )
    gpg_key_fingerprint = gpg.packet_fingerprint(gpg_key)
    ###
    key = gpg.list_keys(gpg.fingerprint)
    key_from_signature = gpg.list_keys(signature_fingerprint)
    key_from_signed_encrypted_message = gpg.list_keys(
        signed_encrypted_message_fingerprint
    )
    key_from_encrypted_message = gpg.list_keys(
        encrypted_message_fingerprint
    )
    key_from_gpg_key = gpg.list_keys(gpg_key_fingerprint)
    ###
    assert key == key_from_signature
    assert key == key_from_signed_encrypted_message
    assert key != key_from_encrypted_message  # anonymous message sender
    assert key == key_from_gpg_key


def test_revoke(gpg):
    raw_list_keys = gpg.raw_list_keys(gpg.fingerprint).replace(" ", "")
    assert "[revoked]" not in raw_list_keys
    try:
        run(gpg.network_import(gpg.fingerprint))
        failed = False
    except:
        failed = True
    finally:
        assert failed  # GnuPG bug #T4393
    gpg.revoke(gpg.fingerprint)
    raw_list_keys = gpg.raw_list_keys(gpg.fingerprint).replace(" ", "")
    assert "[revoked]" in raw_list_keys
    run(gpg.network_export(gpg.fingerprint))
    try:
        run(gpg.network_import(gpg.fingerprint))
        failed = False
    except:
        failed = True
    finally:
        assert failed  # server removes the key after revocation? No.
                       # See https://gitlab.com/hagrid-keyserver/hagrid/issues/137
                       # GnuPG bug #T4393 will cause crash

def test_delete(gpg):
    dev_email = "gonzo.development@protonmail.ch"
    email = "testing_user@testing.testing"
    amount_of_test_keys = 0
    for key_email in gpg.list_keys().values():
        if key_email == email:
            amount_of_test_keys += 1
    gpg.delete(gpg.fingerprint)
    amount_of_test_keys_after_delete = 0
    for key_email in gpg.list_keys().values():
        if key_email == email:
            amount_of_test_keys_after_delete += 1
    assert amount_of_test_keys - 1 == amount_of_test_keys_after_delete
    while True:
        try:
            gpg.delete(gpg.email)
        except:
            break
    while True:
        try:
            gpg.delete("gonzo.development@protonmail.ch")
        except:
            break


def test_auto_fetch_methods(gpg):
    dev_email = "gonzo.development@protonmail.ch"
    dev_fingerprint = "31FDCC4F9961AFAC522A9D41AE2B47FA1EF44F0A"
    message = "test message"
    msg = run(gpg.auto_decrypt(dev_signed_message))
    gpg.verify(dev_signed_message)
    assert msg.strip() == message
    message_fingerprint = gpg.packet_fingerprint(dev_signed_message)
    key_from_message = gpg.list_keys(message_fingerprint)
    key_from_fingerprint = gpg.list_keys(dev_fingerprint)
    assert key_from_message == key_from_fingerprint
    gpg.delete(dev_fingerprint)
    run(gpg.auto_verify(dev_signed_message))
    gpg.delete(dev_fingerprint)


def test_reset_daemon(gpg):
    gpg.reset_daemon()
