# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
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
from tempfile import TemporaryDirectory
from aiohttp import ClientSession
from aiohttp_socks import ProxyConnector


PACKAGE_PATH = str(Path(__file__).absolute().parent.parent)
sys.path.append(PACKAGE_PATH)


from tiny_gnupg import *


legacy_key = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v4.3.0
Comment: https://openpgpjs.org

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
=IoDL
-----END PGP PUBLIC KEY BLOCK-----
"""


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
    global _homedir, _options, _executable, main_passphrase
    print("setup".center(15, "-"))

    username = "testing_user"
    email_address = "testing_user@testing.testing"
    main_passphrase = "test_passphrase"

    tempdir = TemporaryDirectory("testing_tiny_gnupg")
    _homedir = Path(tempdir.name).absolute()
    _options = GnuPGConfig._DEFAULT_OPTIONS_PATH
    _executable = GnuPGConfig._DEFAULT_EXECUTABLE_PATH

    gpg = GnuPG(
        email_address=email_address,
        username=username,
        passphrase=main_passphrase,
        homedir=_homedir,
        options=_options,
        executable=_executable,
    )

    try:
        yield gpg
    finally:
        print("teardown".center(18, "-"))
        tempdir.cleanup()


async def async_method_runner(gpg):
    connector = gpg.keyserver.network.Connector()
    assert connector.__class__ == ProxyConnector
    async with gpg.keyserver.network.Session() as session:
        assert session.__class__ == ClientSession


def test_instance(gpg):
    while True:
        try:
            gpg.delete(gpg.user.email_address)
        except:
            break
    try:
        gpg.config.set_homedir("/ridiculous_root_directory_not_real")
    except FileNotFoundError:
        "Successfully failed to change permissions on an invalid dir. "
        "We refrain from testing on, or making, a priveleged folder "
        "that may actually exist for safety of the tester reasons."
    else:
        raise AssertionError(
            "The instance was able to change the fake directory's "
            "permissions."
        )

    gpg.generate_key()
    user = User(
        email_address=gpg.user.email_address,
        username=gpg.user.username,
        passphrase=main_passphrase,
    )
    config = GnuPGConfig(
        homedir=_homedir,
        options=_options,
        executable=_executable,
    )
    test_gpg = BaseGnuPG(user, config=config)
    test_gpg.generate_key()
    assert gpg.user.username == test_gpg.user.username
    assert gpg.user.email_address == test_gpg.user.email_address
    assert gpg.user.passphrase == test_gpg.user.passphrase
    assert gpg.keyserver.network.port == test_gpg.keyserver.network.port
    assert gpg.keyserver.network.tor_port == test_gpg.keyserver.network.tor_port
    assert gpg.config.homedir == test_gpg.config.homedir
    assert gpg.config.executable == test_gpg.config.executable
    run(async_method_runner(gpg))
    assert gpg.keyserver._search_prefix == test_gpg.keyserver._search_prefix
    assert gpg.keyserver._hostname == test_gpg.keyserver._hostname
    assert str(gpg.keyserver.network.port) in gpg.keyserver._hostname
    assert gpg.keyserver._search_template == test_gpg.keyserver._search_template
    assert gpg._base_command == test_gpg._base_command
    assert gpg._base_passphrase_command == test_gpg._base_passphrase_command
    ###
    assert gpg.keyserver.network.port == 80
    assert gpg.keyserver.network.tor_port == 9050
    assert ".onion" in gpg.keyserver._hostname
    assert ".onion" in gpg.keyserver._search_template
    assert len(gpg.fingerprint) == 40
    assert type(gpg.fingerprint) == str
    assert gpg.config.homedir.endswith("testing_tiny_gnupg")
    assert gpg.user.username == "testing_user"
    assert gpg.config.executable.endswith("gpg2")
    assert gpg.user.passphrase == User._hash_passphrase(b"test_passphrase").hex()
    assert gpg.user.email_address == "testing_user@testing.testing"
    assert gpg.fingerprint in gpg.list_keys()
    assert gpg.fingerprint in gpg.list_keys(secret=True)
    assert test_gpg.fingerprint in gpg.list_keys()
    assert test_gpg.fingerprint in gpg.list_keys(secret=True)
    ###


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
    command = gpg.encode_command(*options)
    passphrase_command = gpg.encode_command(*options, with_passphrase=True)
    for option in options:
        assert option in command
        assert option in passphrase_command
        command.remove(option)
        assert command == gpg.encode_command()
        passphrase_command.remove(option)
        assert passphrase_command == gpg.encode_command(with_passphrase=True)


def test_manual_command(gpg):
    custom_command = gpg.encode_command(manual=True)
    default_command = gpg.encode_command(manual=False)
    default_command.remove("--yes")
    default_command.remove("--batch")
    default_command.remove("--no-tty")
    assert custom_command == default_command
    default_passphrase_command = gpg.encode_command(with_passphrase=True)
    custom_passphrase_command = gpg.encode_command(
        with_passphrase=True, manual=True
    )
    assert default_passphrase_command == custom_passphrase_command


def test_export_import(gpg):
    secret_key = gpg.text_export(gpg.fingerprint, secret=True)
    gpg.text_import(secret_key)
    try:
        failed = False
        gpg.text_export(gpg.fingerprint, secret="Non-boolean value")
    except:
        failed = True
        """Successfully blocked non-boolean"""
    finally:
        assert failed


def test_isolated_identities(gpg):
    """
    Isolated identities do not work as originaly thought. The user must
    choose unique passwords for each identity. Separating keys into
    separate home directories helps only if .
    """
    with TemporaryDirectory("anon_user") as anon_homedir:
        homedir = Path(anon_homedir).absolute()

        user = User(
            username="anon_user",
            email_address="anonymous@testing.testing",
            passphrase="test_passphrase",  # identities are isolated only if
                                         # their passwords are NOT the same!
        )
        config = GnuPGConfig(homedir=str(homedir), executable=_executable)
        anon = BaseGnuPG(user, config=config)

        anon.generate_key()
        anon_uid = anon.fingerprint
        gpg.text_import(anon.text_export(anon_uid))
        anon.text_import(gpg.text_export(gpg.fingerprint))
        ### decrypting
        enc_msg = gpg.encrypt("hi!", uid=anon_uid)
        msg = anon.decrypt(enc_msg)
        try:
            failed = False
            gpg.decrypt(enc_msg)
        except LookupError:
            failed = True
            """
            Same user succefully prevented from decrypting message sent to a
            different identity.
            """
        finally:
            assert failed
        ### signatures
        sig_0 = anon.sign("message", local_user=anon_uid)
        sig_1 = anon.sign("message")
        try:
            failed = False
            gpg.sign("message", local_user=anon_uid)
        except PermissionError:
            failed = True
            """
            Same user successfully prevented from signing message with the
            secret key associated with another identity.
            """
        finally:
            assert failed
        ### encrypting
        try:
            failed = False
            gpg.encrypt("greetings", uid=anon_uid, local_user=anon_uid)
        except PermissionError:
            failed = True
            """
            Same user successfully prevented from signing an encrypted message
            with the secret key associated with another identity.
            """
        finally:
            assert failed
        while True:
            try:
                anon.delete(anon.user.email_address)
            except:
                break


def test_cipher(gpg):
    test_email = "support@keys.openpgp.org"
    run(gpg.network_import(test_email))
    message = "\n  twenty\ntwo\narmed\ndogs\nrush\nthe\nkibble  \n\n"
    for level in range(0, 7):
        for fingerprint in gpg.list_keys():
            try:
                failed = False
                invalid_trust_level = (1 > level or level > 5)
                gpg.set_key_trust(fingerprint, level)
            except ValueError as error:
                # if 1 > int(trust_level) or 5 < int(trust_level):
                """Successfully blocked invlaid trust level"""
                failed = True
            finally:
                assert failed if invalid_trust_level else not failed
        encrypted_message_0 = gpg.encrypt(
            message=message,
            uid=gpg.fingerprint,
            local_user=gpg.fingerprint,
        )
        encrypted_message_1 = gpg.encrypt(
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
            sign=False,
            local_user=gpg.fingerprint,
        )
        assert gpg.decrypt(encrypted_message_0) == message
        assert gpg.decrypt(encrypted_message_1) == message
        signed_message_0 = gpg.sign(message)
        signed_message_1 = gpg.sign(signed_message_0)
        try:
            gpg.sign(message, key="Non boolean value")
            blocked_non_boolean = False
        except:
            """Successfully blocked non-boolean value"""
            blocked_non_boolean = True
        else:
            assert blocked_non_boolean
        gpg.verify(signed_message_0)
        gpg.verify(signed_message_1)
    ###
    try:
        failed = False
        msg = encrypted_message_0
        corrupt_message = msg[:201] + msg[202:]
        gpg.decrypt(corrupt_message)
    except TypeError:
        failed = True
        # The metadata on the message is corrupted by dropping a byte,
        # expectedly leading to an error.
    finally:
        assert failed
    ###
    username = "test_sender"
    email_address = "test_sender@testing.testing"
    passphrase = "test_sender_passphrase"

    user = User(
        email_address=email_address,
        username=username,
        passphrase=passphrase,
    )
    config = GnuPGConfig(homedir=_homedir, executable=_executable)
    sender = BaseGnuPG(user, config=config)

    sender.generate_key()
    sender_key = sender.list_keys(sender.fingerprint)
    sender_pkey = sender.text_export(sender.fingerprint)
    sender_skey = sender.text_export(sender.fingerprint, secret=True)
    msg = sender.encrypt("testing", gpg.fingerprint)
    sender.delete(sender.fingerprint)
    sender._reset_daemon()
    try:
        failed = False
        gpg.decrypt(msg)
    except LookupError as warning:
        failed = True
        gpg.text_import(sender_pkey)
        gpg.list_keys(warning.uid)
    finally:
        assert failed  # fingerprint is subkey of newly added key which
        # was derived from the returned ``decrypt()`` exception ``value``
        # attribute


def test_file_io(gpg):
    path = Path(gpg.config.homedir).absolute()
    file_path = str(path / f"public-key_{gpg.fingerprint}.asc")
    key = gpg.text_export(gpg.fingerprint)
    gpg.file_export(path, gpg.fingerprint)
    gpg.file_import(file_path)
    Path(file_path).unlink()


def test_networking(gpg):
    dev_email = "gonzo.development@protonmail.ch"
    dev_fingerprint = "31FDCC4F9961AFAC522A9D41AE2B47FA1EF44F0A"
    key_url = run(gpg.keyserver.search(dev_email))
    assert "\n" not in key_url
    assert " " not in key_url
    assert "<" not in key_url
    assert ">" not in key_url
    key = run(gpg.keyserver.network.get(key_url))
    gpg.text_import(key)
    assert gpg.list_keys(dev_email)
    fingerprint = gpg.key_fingerprint(dev_email)
    assert dev_fingerprint == fingerprint
    assert fingerprint in gpg.list_keys(dev_fingerprint)
    email = gpg.key_email_address(fingerprint)
    assert dev_email == email
    assert email == gpg.list_keys(dev_email)[fingerprint]
    key_from_email = gpg.text_export(email)
    key_from_fingerprint = gpg.text_export(fingerprint)
    assert key_from_email == key_from_fingerprint
    gpg.text_import(key_from_email)
    # run(gpg.network_import(dev_email))
    try:
        assert key == key_from_email
    except:
        pass  # removed and/or reencoded uids
    finally:
        assert len(gpg.list_keys(dev_email)) == 1
    run(gpg.network_export(gpg.fingerprint))
    test_key_url = run(gpg.keyserver.search(gpg.fingerprint))
    local_key = gpg.text_export(gpg.fingerprint)
    network_key = run(gpg.keyserver.network.get(test_key_url))
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
        failed = False
        run(gpg.network_import("nonsense uid data (HOPEFULLY)"))
    except FileNotFoundError:
        failed = True
        """Successfully failed to retrieve data for bogus query"""
    finally:
        assert failed


def test_network_concurrency(gpg):
    async def gather_looper(gpg, uid):
        tasks = await looper(gpg, uid)
        return await asyncio.gather(*tasks)

    async def looper(gpg, uid):
        tasks = []
        for i in range(2):
            tasks.append(asyncio.ensure_future(gpg.keyserver.search(uid)))
        return tasks

    uid = "support@keys.openpgp.org"
    url = run(gpg.keyserver.search(uid))
    urls = run(gather_looper(gpg, uid))
    assert url.strip()
    for link in urls:
        assert url == link


def test_key_signing(gpg):
    dev_email = "gonzo.development@protonmail.ch"
    dev_fingerprint = "31FDCC4F9961AFAC522A9D41AE2B47FA1EF44F0A"
    command = gpg.encode_command("--check-sigs")
    keyring = gpg.read_output(command)
    gpg.sign(dev_fingerprint, key=True)
    signed_keyring = gpg.read_output(command)
    assert keyring != signed_keyring
    condensed_keyring = signed_keyring.replace(" ", "")
    fingerprint = gpg.fingerprint[-16:]
    assert f"<{dev_email}>\nsig!0x{fingerprint}" in condensed_keyring


def test_packet_parsing(gpg):
    signature = gpg.sign("testing")
    signed_encrypted_message = gpg.encrypt("test", gpg.fingerprint)
    encrypted_message = gpg.encrypt("test", gpg.fingerprint, sign=False)
    gpg_key = gpg.text_export(gpg.fingerprint)
    ###
    signature_fingerprint = gpg._packet_fingerprint(signature)
    signed_encrypted_message_fingerprint = gpg._packet_fingerprint(
        signed_encrypted_message
    )
    encrypted_message_fingerprint = gpg._packet_fingerprint(
        encrypted_message
    )
    gpg_key_fingerprint = gpg._packet_fingerprint(gpg_key)
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
    assert key == key_from_encrypted_message  # better parsing finds fingerprint?
    assert key == key_from_gpg_key


def test_auto_fetch_methods(gpg):
    message = "testing"
    keyserver_email = "support@keys.openpgp.org"
    test_fingerprint = "864C145731DD963466CC7571A2604867523C7ED8"
    dev_email = "gonzo.development@protonmail.ch"
    dev_fingerprint = "31FDCC4F9961AFAC522A9D41AE2B47FA1EF44F0A"
    gpg.delete(dev_fingerprint)
    run(gpg.auto_encrypt(message, dev_fingerprint))
    ###
    ### The server may rate limit queries on the key & cause a crash.
    ### This happens as expected during heavy testing, or when enough
    ### people are running the tests. Wait a bit and try again. This
    ### fetch should pass.
    gpg.delete(dev_fingerprint)
    msg = run(gpg.auto_decrypt(dev_signed_message))
    dev_key = gpg.text_export(dev_fingerprint)
    gpg.text_import(legacy_key)
    assert msg == message
    ###
    packets_0 = gpg._list_packets(dev_signed_encrypted_message)
    packets_1 = gpg._list_packets(dev_encrypted_message)
    packets_2 = gpg._list_packets(dev_signed_message)
    packets_3 = gpg._list_packets(legacy_key)
    packets_4 = gpg._list_packets(dev_key)
    assert type(packets_0) == list
    assert type(packets_1) == list
    assert type(packets_2) == list
    assert type(packets_3) == list
    assert type(packets_4) == list
    assert len(packets_0) == 4
    assert len(packets_1) == 4
    assert len(packets_2) == 11
    assert len(packets_3) == 28
    assert len(packets_4) == 31
    try:
        failed = False
        gpg._list_packets(20 * "Non-OpenPGP data")
    except:
        failed = True
        """Successfully failed when invalid data sent for parsing"""
    finally:
        assert failed
    ###
    fingerprint_0 = gpg._packet_fingerprint(dev_signed_encrypted_message)
    fingerprint_1 = gpg._packet_fingerprint(dev_encrypted_message)
    fingerprint_2 = gpg._packet_fingerprint(dev_signed_message)
    fingerprint_3 = gpg._packet_fingerprint(legacy_key)
    fingerprint_4 = gpg._packet_fingerprint(dev_key)
    fingerprint_0_key = gpg.list_keys(fingerprint_0)
    fingerprint_1_key = gpg.list_keys(fingerprint_1)
    fingerprint_2_key = gpg.list_keys(fingerprint_2)
    fingerprint_3_key = gpg.list_keys(fingerprint_3)
    fingerprint_4_key = gpg.list_keys(fingerprint_4)
    key_from_fingerprint = gpg.list_keys(dev_fingerprint)
    key_from_test_fingerprint = gpg.list_keys(test_fingerprint)
    assert fingerprint_0_key == key_from_test_fingerprint
    assert fingerprint_1_key == key_from_test_fingerprint
    assert fingerprint_2_key == key_from_fingerprint
    assert fingerprint_3_key != key_from_fingerprint
    assert fingerprint_3_key != key_from_test_fingerprint
    assert fingerprint_4_key == key_from_fingerprint
    ###
    try:
        failed_correctly = False
        msg = dev_signed_encrypted_message
        run(gpg.auto_verify(dev_signed_encrypted_message))
    except PermissionError as error:
        failed_correctly = True
    finally:
        assert failed_correctly  # signed encrypted message shows only
        # recipient from the outside (without the decryption key). Tester
        # isn't the recipient, so cannot verify. Nor can verify be used
        # on an encrypted message in general, unless the message is
        # specifcally a signature, not encrypted plaintext. This is just
        # not how verify works. Signatures are on the inside on encrypted
        # messages. So ``decrypt()`` should be used instead, it throws if
        # a signature is invalid on a message.
    try:
        failed = False
        run(gpg.auto_verify(dev_encrypted_message))
    except Exception as exception:
        failed = True
        keyid = exception.uid
        assert gpg.key_email_address(keyid) == gpg.key_email_address(keyserver_email)
    finally:
        assert failed  # signed message shows only recipient from the
        # outside (without the decryption key).
    gpg.delete(dev_fingerprint)
    run(gpg.auto_verify(dev_signed_message))


def test_revoke(gpg):
    raw_list_keys = gpg._raw_list_keys(gpg.fingerprint).replace(" ", "")
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
    raw_list_keys = gpg._raw_list_keys(gpg.fingerprint).replace(" ", "")
    assert "[revoked]" in raw_list_keys
    run(gpg.network_export(gpg.fingerprint))
    try:
        failed = False
        run(gpg.network_import(gpg.fingerprint))
    except:
        failed = True
    finally:
        assert failed  # server removes the key's uid information after
        # revocation now. But this test also fails because of a known
        # bug in GnuPG: bug #T4393 will cause crash.


def test_delete(gpg):
    test_fingerprint = gpg.fingerprint
    number_of_keys_before_delete = len(gpg.list_keys())

    gpg.delete(test_fingerprint)
    keyring_after_delete = gpg.list_keys()
    assert test_fingerprint not in keyring_after_delete
    assert number_of_keys_before_delete == 1 + len(keyring_after_delete)


def test_reset_daemon(gpg):
    gpg._reset_daemon()

