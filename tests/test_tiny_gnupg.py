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


def pop(dictionary):
    return next(iter(dictionary))


dev_signed_encrypted_message = """-----BEGIN PGP MESSAGE-----

hQGMA4/LbsN5/I9OAQwA1eu+s8bp1d6G5GXTAxajqOfuNkUb2/O8y0X1csZv5Mcf
P0xDE3c4m0MVwuJx2UlxWwhLZzVB8gpXj5tOONNDT/AfQw/51EBbNBuMfBC1IgWb
DHYyeuhabZwAAJjbhIjZRk4EvwkIyARD4RrCKaA0m36UVX8jHGFhCJUEyhMErBel
QMU50/2Bt88QPZUnG6en+C9WMjYSKYHJv8+B8MfoXjV6ye4X4ugLnr0/OyknKh9F
46jh+nayCj3TZxlFVP4y2yf3zYhfd7EepZYpsmzTW2GNiy+j0lomvKcnE7nGaRT7
e53Xg1eWrWi3pE0JOiF5tgMngi23eVqQGmaJ3zbjIClpIhopEqXkNP/1oQIAMrK4
JhK/1sugWxYOm0M6xnZ0gfTuf8xSJ4xOzmBb4TE7HvjD6IGQQokzQ/mumlXvZxOy
pymLMTW2yn8CZ5KqOvrC8ObhCYvBUpYRAXcKUpxv+uA1gSlSzH23VSBcSsXJXq5P
TaSnR2yJZDu3PnXCUkr10sAAAbNUS1pLA54EJ38WPhjjSqpHFmPC/ghRoQTn/y37
ka5pvw7ENm0s8N/er6xJyrwGr//8HWebuBxQbRX7MeqYIzgrthfga8xiOF6KKxCC
bRoey0UBYeq6ojXgnV4wLuEffW9O9PB8P+8wpcFNnHufrDV01SHRbxmjysg2JLfD
EkWVGM9BG3EZmnzxp05NsMXsm4srIvjKlaDyNZvwL6h/gm0wE73BjESkQ6OVxwwB
K1nyKCiCMxXW32MA9ax31q0a
=D9D+
-----END PGP MESSAGE-----
"""


dev_encrypted_message = """-----BEGIN PGP MESSAGE-----

hQGMA4/LbsN5/I9OAQv/YCqME/HGJ8goX95twAGjehyenAfdsKG+jU25qUbJ2N2q
YJavKRpodjfLluEI/nQ51Hj+x88DzLrb6W7FtMWO17iHLwSMHXLY+6yw1dg78xeX
59CwaiaUeW3gmibWW5k3btFuZZVlNxwbAAxlWuJJFKauHQwtZUXFAcry3r50+RmE
2GGaZFndfb+F6uPjglsZlrMy0gMnBSRiJEbvHpWSIq9ZOr126stsR7GswV76fjEa
vdrgCeU96B+IGzJt4ltN660BADHb0JwKHAPSnHR4CRfwuEQEZlHlUY3m8oULFRHM
NilZaEF61QMV+o35FZZC7gLqU3hCbpsxygwegdXYMekD0soCH2CkvbvxybzFvjmg
T4QNiHEAXr5J/jJszoXvn+SFir1gyXlBiCdvwIgiSm7vt+/Zzw30GQOv7G4RFI7b
ehci9jSE47vfDzWp7IrCYX1qJy44lcLaTJUafP6bwiOIlHJAEMMu62scbSvRkdgc
0UtU3phsuUC0NbpgmL160kIBqAem1h1z+xGmdj5v/AHW0BABHUbZXubVSVGtcGgS
wAWiDm0xuEmIPI7pFRKVR4VBHvKZsGdbFhLunhdIWfFG7D4=
=VFhI
-----END PGP MESSAGE-----
"""


dev_signed_message = """-----BEGIN PGP MESSAGE-----

owGbwMvMwCW2Ttv9l9wXfy7G07xJDLG/JieVpBaXZOald5SyMIhxMciKKbIY/j3j
PzNx/ZogrbmOMOWsTCC1DFycAjCRtueMDG83FVl0zdX0fFR5cZnRdxde+Y6oyZ6u
1v0z3LfJfe84ZQVUUXN2jWn+vts7Cvf95LsvpOAine63ovP1dfniA7xPmyyZAA==
=I205
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


async def async_method_runner(gpg):
    assert gpg.Connector.__class__ == SocksConnector
    async with gpg.Session as session:
        session.__class__ == ClientSession


def test_instance(gpg):
    while True:
        try:
            gpg.delete(gpg.email)
        except:
            break
    try:
        gpg.set_home_permissions("/ridiculous_root_directory_not_real")
    except:
        """
        Successfully failed to change permissions on an invalid dir.
        We refrain from testing on a root folder that may actually exist
        for safety of the tester reasons.
        """
    gpg.gen_key()
    test_gpg = GnuPG(gpg.username, gpg.email, gpg.passphrase)
    assert gpg.username == test_gpg.username
    assert gpg.email == test_gpg.email
    assert gpg.passphrase == test_gpg.passphrase
    assert gpg.port == test_gpg.port
    assert gpg.tor_port == test_gpg.tor_port
    assert gpg.home == test_gpg.home
    assert gpg.executable == test_gpg.executable
    assert gpg._Connector == test_gpg._Connector
    assert gpg._Session == test_gpg._Session
    run(async_method_runner(gpg))
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
    assert gpg._Connector == SocksConnector
    assert gpg._Session == ClientSession
    assert gpg.port == 80
    assert gpg.tor_port == 9050
    assert ".onion" in gpg.keyserver
    assert ".onion" in gpg.searchserver
    assert gpg.fingerprint in gpg.list_keys()
    assert gpg.fingerprint in gpg.list_keys(secret=True)
    assert test_gpg.fingerprint in gpg.list_keys()
    assert test_gpg.fingerprint in gpg.list_keys(secret=True)


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


def test_export_import(gpg):
    secret_key = gpg.text_export(gpg.fingerprint, secret=True)
    gpg.text_import(secret_key)
    try:
        gpg.text_export(gpg.fingerprint, secret="Non-boolean value")
    except:
        """Successfully blocked non-boolean"""


def test_cipher(gpg):
    test_email = "support@keys.openpgp.org"
    run(gpg.network_import(test_email))
    message = "\n  twenty\ntwo\narmed\ndogs\nrush\nthe\nkibble  \n\n"
    for trust_level in range(0, 7):
        for fingerprint in gpg.list_keys():
            try:
                gpg.trust(fingerprint, trust_level)
            except ValueError as invalid_trust_level:
                if not 0 < int(trust_level) < 6:
                    """Successfully blocked invlaid trust level"""
                    continue
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
        try:
            gpg.sign(message, key="Non boolean value")
        except:
            """Successfully blocked non-boolean value"""
        gpg.verify(signed_message_0)
        gpg.verify(signed_message_1)
        gpg.verify(signed_message_2)
        gpg.verify(signed_message_3)


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
    assert fingerprint == pop(gpg.list_keys(dev_fingerprint))
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
        failed = False
        gpg.text_import(network_key)
    except:
        failed = True  # GnuPG bug #T4393
    finally:
        assert failed
    try:
        failed = False
        run(gpg.network_import(gpg.fingerprint))
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
    try:
        run(gpg.network_import("nonsense uid data (HOPEFULLY)"))
    except FileNotFoundError:
        """Successfully failed to retrieve data for bogus query"""


def test_network_concurrency(gpg):
    async def gather_looper(gpg, uid):
        tasks = await looper(gpg, uid)
        return await asyncio.gather(*tasks)

    async def looper(gpg, uid):
        tasks = []
        for i in range(2):
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


def test_auto_fetch_methods(gpg):
    message = "testing"
    keyserver_email = "support@keys.openpgp.org"
    dev_email = "gonzo.development@protonmail.ch"
    dev_fingerprint = "31FDCC4F9961AFAC522A9D41AE2B47FA1EF44F0A"
    gpg.delete(dev_fingerprint)
    ###
    try:
        msg = run(gpg.auto_decrypt(dev_signed_message))
    except Exception as exception:
        if exception.value == dev_fingerprint:
            """Rate limited on the server"""
            pass
        else:
            raise LookupError(
                f"{exception.value} was returned: {exception} failure"
            )
    dev_key = gpg.text_export(dev_fingerprint)
    assert msg.strip() == message
    ###
    packets_0 = gpg.list_packets(dev_signed_encrypted_message)
    packets_1 = gpg.list_packets(dev_encrypted_message)
    packets_2 = gpg.list_packets(dev_signed_message)
    assert type(packets_0) == list
    assert type(packets_1) == list
    assert type(packets_2) == list
    assert len(packets_0) >= 4
    assert len(packets_1) >= 4
    assert len(packets_2) >= 11
    try:
        gpg.list_packets(20*"Non-OpenPGP data")
    except:
        """Successfully failed when invalid data sent for parsing"""
    ###
    fingerprint_0 = gpg.packet_fingerprint(dev_signed_message)
    fingerprint_1 = gpg.packet_fingerprint(dev_signed_message)
    fingerprint_2 = gpg.packet_fingerprint(dev_signed_message)
    fingerprint_3 = gpg.packet_fingerprint(dev_signed_message)
    fingerprint_0_key = gpg.list_keys(fingerprint_0)
    fingerprint_1_key = gpg.list_keys(fingerprint_1)
    fingerprint_2_key = gpg.list_keys(fingerprint_2)
    fingerprint_3_key = gpg.list_keys(fingerprint_3)
    key_from_fingerprint = gpg.list_keys(dev_fingerprint)
    assert fingerprint_0_key == key_from_fingerprint
    assert fingerprint_1_key == key_from_fingerprint
    assert fingerprint_2_key == key_from_fingerprint
    assert fingerprint_3_key == key_from_fingerprint
    ###
    try:
        failed = False
        run(gpg.auto_verify(dev_signed_encrypted_message))
    except Exception as exception:
        failed = True
        keyid = exception.value
        assert gpg.key_email(keyid) == gpg.key_email(keyserver_email)
    finally:
        assert failed  # signed encrypted message shows only recipient
        # from the outside (without the decryption key).
    try:
        failed = False
        run(gpg.auto_verify(dev_encrypted_message))
    except Exception as exception:
        failed = True
        keyid = exception.value
        assert gpg.key_email(keyid) == gpg.key_email(keyserver_email)
    finally:
        assert failed  # signed message shows only recipient from the
        # outside (without the decryption key).
    gpg.delete(dev_fingerprint)
    run(gpg.auto_verify(dev_signed_message))


def test_revoke(gpg):
    raw_list_keys = gpg.raw_list_keys(gpg.fingerprint).replace(" ", "")
    assert "[revoked]" not in raw_list_keys
    try:
        failed = False
        run(gpg.network_import(gpg.fingerprint))
    except:
        failed = True
    finally:
        assert failed  # GnuPG bug #T4393
        # this should not fail when the bug is resolved
    gpg.revoke(gpg.fingerprint)
    raw_list_keys = gpg.raw_list_keys(gpg.fingerprint).replace(" ", "")
    assert "[revoked]" in raw_list_keys
    run(gpg.network_export(gpg.fingerprint))
    try:
        failed = False
        run(gpg.network_import(gpg.fingerprint))
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
        amount_of_test_keys_after_delete += 1 if key_email == email else 0
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
    while True:
        try:
            gpg.delete("support@keys.openpgp.org")
        except:
            break


def test_reset_daemon(gpg):
    gpg.reset_daemon()
