# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = ["GnuPG", "Network", "run"]


__doc__ = (
    "Implements the wrapper around the users' gpg2 binary so ed25519 "
    "keys can be created & managed from within python."
)


import os
import json
import asyncio
from shlex import quote
from pathlib import Path
from aiohttp import ClientSession
from subprocess import CalledProcessError
from subprocess import check_output, STDOUT
from aiocontext import async_contextmanager
from aiohttp_socks import ProxyConnector, ProxyType


run = asyncio.get_event_loop().run_until_complete


class User:
    """
    A small type for holding user instance information.
    """

    def __init__(self, username, email, *, passphrase):
        self.email = email
        self.username = username
        self.passphrase = passphrase


class Network:
    """
    A simple type to create & manage connections to Tor & the internet.
    """
    ProxyType = ProxyType
    ClientSession = ClientSession
    ProxyConnector = ProxyConnector

    def __init__(self, *, port=80, tor_port=9050):
        self.port = port
        self.tor_port = tor_port

    @property
    def _Connector(self):
        """
        Autoconstruct an aiohttp_socks.ProxyConnector instance.
        """
        return self.ProxyConnector(
            proxy_type=self.ProxyType.SOCKS5,
            host="localhost",
            port=self.tor_port,
            rdns=True,
        )

    @property
    def _Session(self):
        """
        Autoconstruct an aiohttp.ClientSession instance.
        """
        return self.ClientSession(connector=self._Connector)

    @async_contextmanager
    async def network_get(self, url="", **kw):
        """
        Opens a aiohttp.ClientSession.get context manager.
        """
        try:
            session = await self._Session.__aenter__()
            yield await session.get(url, **kw)
        finally:
            await session.close()

    @async_contextmanager
    async def network_post(self, url="", **kw):
        """
        Opens a aiohttp.ClientSession.post context manager.
        """
        try:
            session = await self._Session.__aenter__()
            yield await session.post(url, **kw)
        finally:
            await session.close()

    async def get(self, url="", **kw):
        """
        Returns text of an aiohttp.ClientSession.get request.
        """
        async with self.network_get(url, **kw) as response:
            return await response.text()

    async def post(self, url="", **kw):
        """
        Returns text of an aiohttp.ClientSession.post request.
        """
        async with self.network_post(url, **kw) as response:
            return await response.text()


class GnuPG:
    """
    GnuPG - A linux specific, small, simple & intuitive wrapper for
    creating, using and managing GnuPG's Ed25519 curve keys. This class
    favors reducing code size & complexity with strong, bias defaults
    over flexibility in the api. It's designed to turn the complex,
    legacy, but powerful gnupg system into a fun tool to develop with.

    Usage Example:

    gpg = GnuPG(
        username="user3121",
        email="spicy.salad@email.org",
        passphrase="YesAllBeautifulCats",
        executable="/usr/bin/gpg2",
    )
    """
    _HOME_DIR = Path(__file__).absolute().parent / "gpghome"
    _EXECUTABLE_PATH = _HOME_DIR / "gpg2"
    _OPTIONS_PATH = _HOME_DIR / "gpg2.conf"

    def __init__(
        self,
        *,
        username,
        email,
        passphrase,
        torify=False,
        homedir=None,
        options=None,
        executable=None,
    ):
        """
        Initialize an instance intended to create, manage, or represent
        a single key in the local package gnupg keyring
        """
        self.set_homedir(homedir)
        self.set_options(options)
        self.set_executable(executable)
        self._reset_daemon()
        self.user = User(username, email, passphrase=passphrase)
        self._set_base_command(torify)
        self._set_fingerprint(email)
        self._set_network_variables()

    @classmethod
    def _set_permissions_recursively(cls, path, permissions=0o700):
        """
        Takes a `pathlib.Path` object & recursively sets each sub- file
        & directory's ``permissions``.
        """
        for subpath in path.iterdir():
            os.chmod(subpath, permissions)
            if subpath.is_dir():
                cls._set_permissions_recursively(subpath, permissions)

    def _set_homedir_permissions(self, homedir=None):
        """
        Set safer permissions on the home directory.
        """
        homedir = Path(homedir).absolute() if homedir else self._homedir
        if not homedir.exists():
            problem = "The specified home directory doesn't exist, "
            problem += "which is going to be a problem."
            raise FileNotFoundError(problem)
        os.chmod(homedir, 0o700)
        self._set_permissions_recursively(homedir, 0o700)

    def set_homedir(self, path=None):
        """
        Initialize a home directory for gpg2 binary & data.
        """
        path = Path(path).absolute() if path else self._HOME_DIR
        self._homedir = path
        self.homedir = str(path)
        self._set_homedir_permissions()

    def set_options(self, path=None):
        """
        Initialize a path to the gpg config file.
        """
        path = Path(path).absolute() if path else self._OPTIONS_PATH
        self._options = path
        self.options = str(path)

    def set_executable(self, path=None):
        """
        Initialize a path to the gpg executable binary.
        """
        path = Path(path).absolute() if path else self._EXECUTABLE_PATH
        self._executable = path
        self.executable = str(path)

    def _set_base_command(self, torify=False):
        """
        Construct the default commands used to call gnupg2.
        """
        torify = ["torify"] if torify else []
        self._base_command = torify + [
            self.executable,
            "--yes",
            "--batch",
            "--quiet",
            "--no-tty",
            "--options",
            self.options,
            "--homedir",
            self.homedir,
        ]
        self._base_passphrase_command = self._base_command + [
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
        ]

    def _set_fingerprint(self, uid=""):
        """
        Populate ``fingerprint`` attribute for persistent user.
        """
        try:
            self.fingerprint = self.key_fingerprint(uid)
        except:
            self.fingerprint = ""

    def _set_network_variables(
        self,
        *,
        port=80,
        tor_port=9050,
        keyserver=(
            "http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4i"
            "qmbad.onion"
        ),
        search_prefix="search?q=",
    ):
        """
        Set network variables for adaptable implementations.
        """
        self.network = Network(port=port, tor_port=tor_port)
        self._keyserver_host = keyserver.strip("/").strip()
        self._search_prefix = search_prefix.strip("/").strip()

    @property
    def _keyserver(self):
        """
        Autoconstruct keyserver URL with adaptable port number.
        """
        return f"{self._keyserver_host}:{self.network.port}/"

    @property
    def _keyserver_export_api(self):
        """
        Autoconstruct specific keyserver key upload api URL.
        """
        return self._keyserver + "vks/v1/upload"

    @property
    def _keyserver_verify_api(self):
        """
        Autoconstruct specific keyserver key verification api URL.
        """
        return self._keyserver + "vks/v1/request-verify"

    @property
    def _searchserver(self):
        """
        Autoconstruct specific keyserver search URL.
        """
        return f"{self._keyserver}{self._search_prefix}"

    def encode_command(
        self, *options, with_passphrase=False, manual=False
    ):
        """
        Autoformats gpg2 commands soley from additional options.
        """
        if with_passphrase:
            return self._base_passphrase_command + [*options]
        elif not manual:
            return self._base_command + [*options]
        else:
            cmd = self._base_command.copy() + [*options]
            cmd.remove("--yes")
            cmd.remove("--batch")
            cmd.remove("--no-tty")
            return cmd

    def encode_inputs(self, *inputs):
        """
        Prepares inputs *X for subprocess.check_output(input=*X).
        """
        return ("\n".join(inputs) + "\n").encode()

    def read_output(self, command=(), inputs=b"", **kw):
        """
        Quotes terminal escape characters & runs user commands.
        """
        try:
            return check_output(
                [quote(part) for part in command], input=inputs, **kw
            ).decode()
        except Exception as source:
            error = source
        try:
            kw.pop("stderr") if "stderr" in kw else 0
            check_output(
                [quote(part) for part in command],
                input=inputs,
                stderr=STDOUT,
                **kw,
            ).decode()
        except CalledProcessError as permissions_check:
            notice = "Passphrase wrong, inexistent key, or invalid rights "
            notice += "to access secret key."
            warning = PermissionError(notice)
            warning.inputs = inputs
            warning.command = command
            warning.output = permissions_check.output.decode()
            print(warning.output)
            raise warning if "Bad passphrase" in warning.output else error

    def gen_key(self):
        """
        Generates a set of ed25519 keys with isolated roles:
        Main Key    - Certification
            Subkey  - Signing
            Subkey  - Authentication
            Subkey  - Encryption
        """
        command = self.encode_command(
            "--expert",
            "--full-gen-key",
            "--with-colons",
            "--command-fd",
            "0",
            "--status-fd",
            "1",
            with_passphrase=True,
        )
        command.remove("--batch")
        inputs = self.encode_inputs(
            self.user.passphrase,
            "11",
            "S",
            "Q",
            "1",
            "3y",
            "y",
            self.user.username,
            self.user.email,
            "",
            "O",
        )
        output = self.read_output(command, inputs, stderr=STDOUT)
        self.fingerprint = output.strip().split("\n")[-1][-40:]
        self._add_subkeys(self.fingerprint)

    def _add_subkeys(self, uid=""):
        """
        Adds three subkeys with isolated roles to key matching ``uid``:
        ``uid`` Key
            Subkey  - Signing
            Subkey  - Authentication
            Subkey  - Encryption
        """
        command = self.encode_command(
            "--command-fd",
            "0",
            "--edit-key",
            "--expert",
            uid,
            with_passphrase=True,
        )
        inputs = self.encode_inputs(
            self.user.passphrase,
            "addkey",
            "10",
            "1",
            "3y",
            "addkey",
            "11",
            "A",
            "S",
            "Q",
            "1",
            "3y",
            "addkey",
            "12",
            "1",
            "3y",
            "save",
        )
        self.read_output(command, inputs, stderr=STDOUT)

    def delete(self, uid=""):
        """
        Deletes secret & public key matching ``uid`` from keyring.
        """
        if len(uid) < 4:
            raise ValueError("No ``uid`` was specified.")
        uid = self.key_fingerprint(uid)  # avoid non-fingerprint uid crash
        if uid in self.list_keys(secret=True):
            command = self.encode_command(
                "--command-fd", "0", "--delete-secret-keys", uid
            )
            inputs = self.encode_inputs("y", "y")
            self.read_output(command, inputs)
        command = self.encode_command(
            "--command-fd", "0", "--delete-key", uid
        )
        inputs = self.encode_inputs("y")
        return self.read_output(command, inputs)

    def revoke(self, uid=""):
        """
        Generates & imports revocation cert for key matching ``uid``,
        returns the revoked key.
        """
        if len(uid) < 4:
            raise ValueError("No ``uid`` was specified.")
        uid = self.key_fingerprint(uid)
        command = self.encode_command(
            "--command-fd", "0", "--gen-revoke", uid, with_passphrase=True
        )
        command.remove("--batch")
        inputs = self.encode_inputs(
            self.user.passphrase, "y", "0", " ", "y"
        )
        revoke_cert = self.read_output(command, inputs)
        self.text_import(revoke_cert)
        return self.text_export(uid)

    def set_key_trust(self, uid="", level=5):
        """
        Sets trust ``level`` to key matching ``uid`` in the keyring.
        """
        uid = self.key_fingerprint(uid)
        level = str(int(level))
        if not 1 <= int(level) <= 5:
            raise ValueError("Trust levels must be between 1 and 5.")
        command = self.encode_command(
            "--edit-key", "--command-fd", "0", uid
        )
        inputs = self.encode_inputs("trust", level, "y", "save")
        return self.read_output(command, inputs)

    def _raw_packets(self, target=""):
        """
        Returns OpenPGP metadata from ``target`` in raw string format.
        """
        command = self.encode_command(
            "--pinentry-mode",
            "cancel",
            "-vv",
            "--list-packets",
            "--show-session-key",
        )
        command.remove("--batch")
        inputs = self.encode_inputs(target)
        try:
            return self.read_output(command, inputs, stderr=STDOUT)
        except CalledProcessError as error:
            notice = "Can't decrypt all packets without secret key."
            warning = KeyError(notice)
            warning.value = error.output.decode()
            raise warning if "No secret key" in warning.value else error

    def _list_packets(self, target=""):
        """
        Returns OpenPGP metadata from ``target`` in list format.
        """
        try:
            packets = self._raw_packets(target).split("\n\t")
        except KeyError as warning:
            packets = warning.value.split("\n\t")
        except CalledProcessError as warning:
            notice = f"``target`` doesn't seem to be valid OpenPGP data."
            error = TypeError(notice)
            error.value = target
            error.output = warning.output
            raise error
        listed_packets = []
        for packet in packets:
            listed_packets.append(packet.strip().split("\n"))
        return listed_packets

    def _packet_fingerprint(self, target=""):
        """
        Returns the sender's key fingerprint scraped from ``target``, a
        gpg message, key or signature.
        """
        try:
            packets = self._raw_packets(target).replace(")", "")
        except KeyError as warning:
            packets = warning.value.replace(")", "")
        except CalledProcessError as warning:
            notice = f"``target`` doesn't seem to be valid OpenPGP data."
            error = TypeError(notice)
            error.value = target
            error.output = warning.output
            raise error
        packets = packets.replace("key ID", "keyid")
        if "(issuer fpr" in packets:
            size = slice(-40, None)
            sentinel = "(issuer fpr"
        else:
            sentinel = "keyid "
            size = slice(-16, None)
        for packet in packets.split("\n\t"):
            if sentinel in packet:
                return packet[size]

    def encrypt(self, message="", uid="", sign=True, local_user=""):
        """
        Encrypts ``message`` to key matching ``uid`` & signs with key
        matching ``local_user`` or defaults to instance key. Optionally,
        if ``sign`` == False, ``message`` won't be signed.
        """
        self._reset_daemon() if sign else 0
        uid = self.key_fingerprint(uid)  # avoid wkd lookups
        command = self.encode_command(
            "--command-fd",
            "0",
            "--local-user",
            local_user if local_user else self.fingerprint,
            "-esar" if sign else "-ear",
            uid,
            with_passphrase=True,
        )
        if self.key_trust(uid) != "ultimate":
            command.remove("--batch")  # avoid crash with untrusted keys
            inputs = self.encode_inputs(self.user.passphrase, "y", message)
        else:
            inputs = self.encode_inputs(self.user.passphrase, message)
        return self.read_output(command, inputs[:-1])

    async def auto_encrypt(
        self, message="", uid="", sign=True, local_user=""
    ):
        """
        Queries keyserver before encryption if recipient's ``uid`` key
        isn't in the local keyring.
        """
        try:
            return self.encrypt(message, uid, sign, local_user)
        except LookupError as uid:
            await self.network_import(uid.value)
            return self.encrypt(message, uid.value, sign, local_user)

    def decrypt(self, message=""):
        """
        Decrypts ``message`` autodetecting correct key from keyring.
        """
        self._reset_daemon()
        fingerprint = self._packet_fingerprint(message)
        fingerprint = self.key_fingerprint(fingerprint)
        try:
            command = self.encode_command("-d", with_passphrase=True)
            inputs = self.encode_inputs(self.user.passphrase, message)
            return self.read_output(command, inputs)
        except CalledProcessError:
            pass
        try:
            self.read_output(command, inputs, stderr=STDOUT)
        except CalledProcessError as error:
            error_lines = error.output.decode().strip().split("\n")
            sentinel = "gpg:                using"
            uid = [line[-40:] for line in error_lines if sentinel in line]
            uid = uid[-1] if uid else ""
            notice = f"UID '{uid}' not in the instance's keyring."
            warning = LookupError(notice)
            warning.value = uid if uid else fingerprint
            raise warning

    async def auto_decrypt(self, message=""):
        """
        Queries keyserver before decryption if ``message`` signature key
        isn't in the local keyring.
        """
        try:
            return self.decrypt(message)
        except LookupError as fingerprint:
            await self.network_import(fingerprint.value)
            return self.decrypt(message)

    def sign(self, target="", local_user="", *, key=False):
        """
        Signs key matching ``target`` uid with a key matching ``local_user``
        uid or the instance default. Optionally signs ``target`` message
        if ``key`` == False.
        """
        self._reset_daemon()
        if key == True:  # avoid truthiness
            command = self.encode_command(
                "--local-user",
                local_user if local_user else self.fingerprint,
                "--sign-key",
                target,
                with_passphrase=True,
            )
            inputs = self.encode_inputs(self.user.passphrase)
        elif key == False:
            command = self.encode_command(
                "--local-user",
                local_user if local_user else self.fingerprint,
                "-as",
                with_passphrase=True,
            )
            inputs = self.encode_inputs(self.user.passphrase, target)[:-1]
        else:
            raise TypeError(f"``key`` != boolean, {type(key)} given.")
        return self.read_output(command, inputs)

    def verify(self, message=""):
        """
        Verifies signed ``message`` if the corresponding public key is
        in the local keyring.
        """
        self._reset_daemon()
        fingerprint = self._packet_fingerprint(message)
        fingerprint = self.key_fingerprint(fingerprint)
        try:
            command = self.encode_command("--verify")
            inputs = self.encode_inputs(message)
            return self.read_output(command, inputs)
        except CalledProcessError:
            notice = f"``message`` is unverifiable."
            error = PermissionError(notice)
            error.value = fingerprint
            raise error

    async def auto_verify(self, message=""):
        """
        Queries keyserver before verifying ``message`` if its signature
        key isn't in the local keyring.
        """
        try:
            return self.verify(message)
        except LookupError as fingerprint:
            await self.network_import(fingerprint.value)
            return self.verify(message)

    def _raw_list_keys(self, uid="", secret=False):
        """
        Returns the terminal output of the --list-keys ``uid`` option.
        """
        secret = "secret-" if secret == True else ""
        if uid:
            command = self.encode_command(f"--list-{secret}keys", uid)
        else:
            command = self.encode_command(f"--list-{secret}keys")
        try:
            return self.read_output(command)
        except CalledProcessError:
            notice = f"UID '{uid}' not in package {secret}keyring"
            warning = LookupError(notice)
            warning.value = uid
            raise warning

    def _format_list_keys(self, raw_list_keys_terminal_output, secret):
        """
        Returns a dict of fingerprints & email addresses scraped from
        the terminal output of the --list-keys option.
        """
        sentinel = "sec" if secret == True else "pub"
        keys = raw_list_keys_terminal_output.split(f"\n{sentinel} ")
        fingerprints = [
            part[part.find("\nuid") - 40 : part.find("\nuid")]
            for part in keys
            if "\nuid" in part
        ]
        emails = [
            self.key_email(fingerprint) for fingerprint in fingerprints
        ]
        return dict(zip(fingerprints, emails))

    def list_keys(self, uid="", *, secret=False):
        """
        Returns a dict of fingerprints & email addresses of all keys in
        the local keyring, or optionally the key matching ``uid``.
        """
        return self._format_list_keys(
            self._raw_list_keys(uid, secret), secret
        )

    def key_email(self, uid=""):
        """
        Returns the email address on the key matching ``uid``.
        """
        if len(uid) < 4:
            raise ValueError("No ``uid`` was specified.")
        parts = self._raw_list_keys(uid).replace(" ", "")
        for part in parts.split("\nuid"):
            if "@" in part and "]" in part:
                part = part[part.find("]") + 1 :]
                if "<" in part and ">" in part:
                    part = part[part.find("<") + 1 : part.find(">")]
                return part

    def key_fingerprint(self, uid=""):
        """
        Returns the fingerprint on the key matching ``uid``.
        """
        if len(uid) < 4:
            raise ValueError("No ``uid`` was specified.")
        return next(iter(self.list_keys(uid)))

    def key_trust(self, uid=""):
        """
        Returns the current trust level on the key matching ``uid``.
        """
        if len(uid) < 4:
            raise ValueError("No ``uid`` was specified.")
        key = self._raw_list_keys(uid).replace(" ", "")
        trust = key[key.find("\nuid[") + 5 :]
        return trust[: trust.find("]")]

    def _reset_daemon(self):
        """
        Resets the gpg-agent daemon.
        """
        command = [
            "gpgconf", "--homedir", self.homedir, "--kill", "gpg-agent"
        ]
        kill_output = self.read_output(command)
        command = ["gpg-agent", "--homedir", self.homedir, "--daemon"]
        reset_output = self.read_output(command)
        return kill_output, reset_output

    async def _raw_search(self, query=""):
        """
        Returns HTML of keyserver key search matching ``query`` uid.
        """
        url = f"{self._searchserver}{query}"
        print(f"querying: {url}")
        return await self.network.get(url)

    async def search(self, query=""):
        """
        Returns keyserver URL of the key found from ``query`` uid.
        """
        query = query.replace("@", "%40").replace(" ", "%20")
        response = await self._raw_search(query)
        if "We found an entry" not in response:
            return ""
        url_part = self._keyserver_host
        url_part = response[response.find(f"{url_part}") :]
        return url_part[: url_part.find('>') - 1]

    async def network_import(self, uid=""):
        """
        Imports the key matching ``uid`` from the keyserver.
        """
        key_url = await self.search(uid)
        if not key_url:
            raise FileNotFoundError(f"UID '{uid}' not found on server.")
        print(f"key location: {key_url}")
        key = await self.network.get(key_url)
        print(f"downloaded:\n{key}")
        return self.text_import(key)

    def file_import(self, path=""):
        """
        Imports a key from the file located at ``path``.
        """
        with open(path, "r") as keyfile:
            key = keyfile.read()
        return self.text_import(key)

    def text_import(self, key=""):
        """
        Imports the ``key`` string into the local keyring.
        """
        command_bugfix = self.encode_command(
            "--import-options", "import-drop-uids", "--import"
        )
        # "--import-options", "import-drop-uids" needed to allow import
        # of keys without uids from Hagrid-like keyservers. Doesn't work
        # b/c of a bug in GnuPG. Pass the option to allow the patch to
        # take effect if/when one is available.
        command = self.encode_command("--import")
        inputs = self.encode_inputs(key)
        try:
            fingerprint = self._packet_fingerprint(key)
            return self.read_output(command_bugfix, inputs, stderr=STDOUT)
        except CalledProcessError:
            pass
        try:
            return self.read_output(command, inputs, stderr=STDOUT)
        except CalledProcessError as error:
            notice = f"{fingerprint} key isn't importable."
            notice += " See https://dev.gnupg.org/T4393"
            warning = KeyError(notice)
            warning.value = key
            warning.output = error.output.decode()
            raise warning if "no user ID" in warning.output else error

    async def _raw_api_export(self, uid=""):
        """
        Uploads the key matching ``uid`` to the keyserver. Returns a json
        string that looks like ->
        '''{
            "key-fpr": self.key_fingerprint(uid),
            "status": {self.key_email(uid): "unpublished"},
            "token": api_token,
        }'''
        """
        key = self.text_export(uid)
        url = self._keyserver_export_api
        print(f"contacting: {url}")
        print(f"exporting:\n{key}")
        payload = {"keytext": key}
        return await self.network.post(url, json=payload)

    async def _raw_api_verify(self, payload=""):
        """
        Prompts the keyserver to verify the list of email addresses in
        ``payload``["addresses"] with the api_token in ``payload``["token"].
        The keyserver then sends a confirmation email asking for consent
        to publish the uid information with the key that was uploaded.
        """
        url = self._keyserver_verify_api
        print(f"sending verification to: {url}")
        return await self.network.post(url, json=payload)

    async def network_export(self, uid=""):
        """
        Exports the key matching ``uid`` to the keyserver.
        """
        response = json.loads(await self._raw_api_export(uid))
        payload = {
            "addresses": [self.key_email(uid)],
            "token": response["token"],
        }
        response = json.loads(await self._raw_api_verify(payload))
        print(f"check {payload['addresses'][0]} for confirmation.")
        return response

    def file_export(
        self, path="", uid="", *, secret=False
    ):
        """
        Exports the public key matching ``uid`` to the ``path`` directory.
        If ``secret`` == True then exports the secret key that matches
        ``uid``.
        """
        key = self.text_export(uid, secret=secret)
        fingerprint = self.key_fingerprint(uid)
        filename = Path(path).absolute() / (fingerprint + ".asc")
        with open(filename, "w+") as keyfile:
            return keyfile.write(key)

    def text_export(self, uid="", *, secret=False):
        """
        Returns a public key string that matches ``uid``. Optionally,
        returns the secret key as a string that matches ``uid`` if
        ``secret`` == True.
        """
        uid = self.key_fingerprint(uid)
        if secret == True:  # avoid truthiness
            command = self.encode_command(
                "-a", "--export-secret-keys", uid, with_passphrase=True
            )
            inputs = self.encode_inputs(self.user.passphrase)
            return self.read_output(command, inputs)
        elif secret == False:
            command = self.encode_command("-a", "--export", uid)
            return self.read_output(command)
        else:
            raise TypeError(f"``secret`` != boolean, {type(secret)} given")

