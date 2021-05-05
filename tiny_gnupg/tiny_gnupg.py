# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "GnuPG",
    "User",
    "Network",
    "Terminal",
    "MessageBus",
    "Error",
    "Issue",
    "run",
]


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
from typing import Any, Hashable, Iterable, Union
from aiohttp_socks import ProxyConnector, ProxyType


run = asyncio.get_event_loop().run_until_complete


class User:
    """
    A small type for holding `GnuPG` user instance information.
    """

    def __init__(self, username: str, email: str, *, passphrase: str):
        self.email = email
        self.username = username
        self.passphrase = passphrase


class Network:
    """
    A simple type to create & manage connections to Tor & the internet.
    """

    _PORT = 80
    _TOR_PORT = 9050
    _ProxyType = ProxyType
    _ClientSession = ClientSession
    _ProxyConnector = ProxyConnector

    def __init__(self, *, port=_PORT, tor_port=_TOR_PORT):
        self.port = port
        self.tor_port = tor_port

    def Connector(
        self, *, proxy_type=None, host=None, port=None, rdns=True, **kw
    ):
        """
        Autoconstruct an aiohttp_socks.ProxyConnector instance.
        """
        return self._ProxyConnector(
            proxy_type=proxy_type if proxy_type else self._ProxyType.SOCKS5,
            host=host if host else "localhost",
            port=port if port else self.tor_port,
            rdns=rdns,
            **kw,
        )

    def Session(self, *, connector: ProxyConnector = None, **kw):
        """
        Autoconstruct an aiohttp.ClientSession instance.
        """
        connector = connector if connector else self.Connector()
        return self._ClientSession(connector=connector, **kw)

    @async_contextmanager
    async def context_get(self, url: str, **kw):
        """
        Opens a aiohttp.ClientSession.get context manager.
        """
        try:
            session = await self.Session().__aenter__()
            yield await session.get(url, **kw)
        finally:
            await session.close()

    @async_contextmanager
    async def context_post(self, url: str, **kw):
        """
        Opens a aiohttp.ClientSession.post context manager.
        """
        try:
            session = await self.Session().__aenter__()
            yield await session.post(url, **kw)
        finally:
            await session.close()

    async def get(self, url: str, **kw):
        """
        Returns text of an aiohttp.ClientSession.get request.
        """
        async with self.context_get(url, **kw) as response:
            return await response.text()

    async def post(self, url: str, **kw):
        """
        Returns text of an aiohttp.ClientSession.post request.
        """
        async with self.context_post(url, **kw) as response:
            return await response.text()


class MessageBus:
    """
    This type carries values that can be added to & queried from an
    instance through dotted or bracketed syntax. It's used in the
    `tiny_gnupg` package to carry values between user code & the output
    of commands sent to the terminal.
    """

    def __init__(self, mapping={}, **kwargs):
        kw = mapping if mapping.__class__ == dict else json.loads(mapping)
        self.__dict__.update({**kw, **kwargs})

    def __setitem__(self, key: Hashable, value: Any):
        self.__dict__[key] = value

    def __delitem__(self, key: Hashable):
        del self.__dict__[key]

    def __getitem__(self, key: Hashable):
        try:
            return self.__dict__[key]
        except KeyError:
            return getattr(self, key)


class Terminal:
    """
    This type functions as a helpful & pythonic abstraction for sending
    commands to a terminal, reading their outputs, & handling errors
    that arise from those calls.

    Usage Example:

    from subprocess import STDOUT
    from subprocess import CalledProcessError

    def error_handler(terminal, error):
        if not isinstance(error, CalledProcessError):
            raise error
        print(error.output)
        # Do some error handling in this function

    def teardown_logic(terminal):
        print(terminal.bus.result)
        # Code in this function is always run after a context


    handlers = dict(if_exception=error_handler, finally_run=teardown_logic)

    with Terminal(**handlers) as terminal:
        terminal.bus.result = terminal.enter(["ls", "-al"], stderr=STDOUT)
    """

    @staticmethod
    def _if_exception(self, error: Exception, *a, **kw):
        """
        A placeholder method which is run after an execption is raised
        within the class' context manager if another function isn't
        specified.
        """
        raise error

    @staticmethod
    def _finally_run(self, *a, **kw):
        """
        A placeholder method which is run in a finally block after the
        class' context manager is finished if another function isn't
        specified.
        """
        return

    @staticmethod
    def enter(command: Iterable[str], inputs=b"", *, decode=True, **kw):
        """
        Quotes terminal escape characters & runs user commands.
        """
        result = check_output(
            [quote(part) for part in command], input=inputs, **kw
        )
        return result.decode() if decode else result

    def __init__(self, *, if_exception=None, finally_run=None):
        """
        Inserts methods into the instance which will be run after the
        class' context manager, one if an execption occurs, & the other
        in a finally block.
        """
        self.bus = MessageBus()
        self.if_exception = (
            if_exception if if_exception else self._if_exception
        )
        self.finally_run = finally_run if finally_run else self._finally_run

    def __enter__(self):
        """
        Opens a context manager which catches execptions that will be
        handled from within the `__exit__` method.
        """
        return self

    def __exit__(self, exc_type=None, exc_value=None, traceback=None):
        """
        Runs the instance's `if_exception` & `finally_run` methods after
        an exception is raised or the context closes. If the return
        value of the `if_exception` method is `True` then all exceptions
        within the context will be surpressed.
        """
        try:
            if exc_type:
                error = exc_value if exc_value else exc_type
                return self.if_exception(self, error)
        finally:
            self.finally_run(self)


class Error:
    """
    This type helps to separate the error handling logic from the GnuPG
    class with pythonic abstractions. This class' methods are instructed
    to be run after exceptions are raised within a `Terminal` class'
    context manager.
    """

    _BAD_PASSPHRASE_OR_MISSING_KEY = (
        "Passphrase wrong, inexistent key, or invalid rights to access "
        "secret key."
    )
    _PACKETS_PROTECTED_BY_SECRET_KEY = (
        "Can't decrypt all packets without the corresponding secret key."
    )
    _INVALID_TARGET_OPENPGP_DATA = (
        "The ``target`` doesn't seem to be valid OpenPGP data."
    )
    _KEY_WITH_UID_ISNT_IN_KEYRING = (
        "Key with UID '_UID_' isn't in the instance's _SECRET_keyring."
    )
    _SIGNATURES_PUBLIC_KEY_ISNT_IN_KEYRING = (
        "Key with UID '_UID_' isn't in the instance's keyring."
    )
    _KEY_ISNT_IMPORTABLE = (
        "Key with UID '_UID_' isn't importable. See https://dev.gnupg.o"
        "rg/T4393."
    )
    _MESSAGE_IS_UNVERIFIABLE = "The ``message`` is unverifiable."

    @classmethod
    def _key_with_uid_isnt_in_keyring(cls, uid: str, secret: bool):
        """
        Inserts the ``uid`` of the key causing an error into a static
        string that's reported to the user. Also inserts a conditional
        string to signal if the key was being checked for among the
        instance's ``secret`` keys.
        """
        secret = "secret-" if secret else ""
        error = cls._KEY_WITH_UID_ISNT_IN_KEYRING
        return error.replace("_UID_", uid).replace("_SECRET_", secret)

    @classmethod
    def _signatures_public_key_isnt_in_keyring(cls, uid: str):
        """
        Inserts the ``uid`` of the key causing an error into a static
        string that's reported to the user.
        """
        error = cls._SIGNATURES_PUBLIC_KEY_ISNT_IN_KEYRING
        return error.replace("_UID_", uid)

    @classmethod
    def _key_isnt_importable(cls, uid: str):
        """
        Inserts the ``uid`` of the key causing an error into a static
        string that's reported to the user.
        """
        return cls._KEY_ISNT_IMPORTABLE.replace("_UID_", uid)

    @staticmethod
    def _raise_unexpected_error(error: Exception):
        """
        Raises any non-`CalledProcessError` so it isn't processed any
        further by an error handling method.
        """
        if error.__class__ != CalledProcessError:
            raise error

    @classmethod
    def no_permission(cls, terminal: Terminal, error: Exception):
        """
        If either the user's passphrase is wrong, or the key they're
        wanting to use isn't owned by their current instance, or the key
        isn't in the instance's keyring, then an error is raised. This
        method runs a command again after failure to catch the error's
        outputs to inform the user.
        """
        cls._raise_unexpected_error(error)
        try:
            bus = terminal.bus
            bus.kw.pop("stderr") if "stderr" in bus.kw else 0
            terminal.enter(bus.command, bus.inputs, stderr=STDOUT, **bus.kw)
        except CalledProcessError as permissions_check:
            warning = PermissionError(cls._BAD_PASSPHRASE_OR_MISSING_KEY)
            warning.inputs = bus.inputs
            warning.command = bus.command
            warning.output = permissions_check.output.decode()
            bad_passphrase = "Bad passphrase" in warning.output
            missing_key = "No secret key" in warning.output
            raise warning if (bad_passphrase or missing_key) else error

    @classmethod
    def secret_packets(cls, terminal: Terminal, error: Exception):
        """
        If OpenPGP data packets are encrypted it causes an error. This
        method is run after a read failure to inform the user the data
        needs to be decrypted successfully before reading its OpenPGP
        data.
        """
        cls._raise_unexpected_error(error)
        warning = KeyError(cls._PACKETS_PROTECTED_BY_SECRET_KEY)
        warning.packets = error.output.decode()
        raise warning if "No secret key" in warning.packets else error

    @classmethod
    def invalid_pgp_packets(cls, terminal: Terminal, error: Exception):
        """
        If some target data doesn't contain correctly formatted OpenPGP
        data packets it causes an error. This method is run after a read
        failure to inform the user something is wrong with the data that
        was provided.
        """
        if error.__class__ == KeyError:
            terminal.bus.packets = error.packets
            return True
        else:
            cls._raise_unexpected_error(error)
            warning = TypeError(cls._INVALID_TARGET_OPENPGP_DATA)
            warning.target = terminal.bus.target
            warning.packets = error.output.decode()
            raise warning

    @classmethod
    def cannot_list_key(cls, terminal: Terminal, error: Exception):
        """
        Searching for a UID which isn't contained by any key in the
        instance's keyring causes an error. This method is run after a
        search failure to inform the user the UID they provided doesn't
        match a key in their instance's keyring.
        """
        cls._raise_unexpected_error(error)
        uid, secret = terminal.bus.uid, terminal.bus.secret
        warning = LookupError(
            cls._key_with_uid_isnt_in_keyring(uid, secret)
        )
        warning.uid = terminal.bus.uid
        raise warning

    @staticmethod
    def _pull_uid_from_signature_error(
        terminal: Terminal, error: Exception
    ):
        """
        Returns the signing key's UID from the gpg2 error message caused
        by trying to verify a signature without having the corresponding
        public key in the instance's keyring.
        """
        sentinel = "gpg:using"
        error_lines = error.output.decode().replace(" ", "").split("\n")
        uid = [line[-40:] for line in error_lines if sentinel in line]
        return uid[-1] if uid else terminal.bus.uid

    @classmethod
    def no_signature_key(cls, terminal: Terminal, error: Exception):
        """
        Decrypting an OpenPGP message which contains a signature causes
        an error if the public key associated with the signature isn't
        in the instance's keyring. An error is also possible if the user
        doesn't have the correct passphrase or decryption key. This
        method runs the decryption again after a failure to determine
        the issue & correctly inform the user.
        """
        cls._raise_unexpected_error(error)
        try:
            bus = terminal.bus
            terminal.enter(bus.command, bus.inputs, stderr=STDOUT)
        except CalledProcessError as err:
            uid = cls._pull_uid_from_signature_error(terminal, err)
            warning = LookupError(
                cls._signatures_public_key_isnt_in_keyring(uid)
                if uid not in bus.keys()
                else cls._BAD_PASSPHRASE_OR_MISSING_KEY
            )
            warning.uid = uid
            raise warning

    @classmethod
    def unverifiable_message(cls, terminal: Terminal, error: Exception):
        """
        Both an invalid signature & not having a signature's public key
        in the instance's keyring will cause an error. This method is
        run after such verification errors to inform the user.
        """
        cls._raise_unexpected_error(error)
        warning = PermissionError(cls._MESSAGE_IS_UNVERIFIABLE)
        warning.uid = terminal.bus.uid
        raise warning

    @classmethod
    def key_isnt_importable(cls, terminal: Terminal, error: Exception):
        """
        Since GnuPG can't import keys without user ID's, this method is
        run after an import failure to inform the user of this bug in
        GnuPG if it was the cause of the error.
        """
        cls._raise_unexpected_error(error)
        warning = KeyError(cls._key_isnt_importable(terminal.bus.uid))
        warning.key = terminal.bus.key
        warning.output = error.output.decode()
        raise warning if "no user ID" in warning.output else error


class Issue:
    """
    This type helps improve readability & concern separation within the
    GnuPG class when general issues are encountered.
    """

    _HOME_DIRECTORY_DOESNT_EXIST = (
        "The specified home directory doesn't exist, which is going to "
        "be a problem."
    )
    _KEY_KEYWORD_ARGUMENT_ISNT_A_BOOL = (
        "type(``key``) != bool, _TYPE_ was given."
    )
    _SECRET_KEYWORD_ARGUMENT_ISNT_A_BOOL = (
        "type(``secret``) != bool, _TYPE_ was given."
    )
    _TRUST_LEVELS_MUST_BE_BETWEEN_1_AND_5 = (
        "Trust levels must be between 1 and 5, inclusively (1, 5)."
    )
    _UID_WASNT_LOCATED_ON_THE_KEYSERVER = (
        "Key with UID '_UID_' wasn't found on the keyserver."
    )
    _INADEQUATE_LENGTH_UID_WAS_GIVEN = (
        "Key with UID '_UID_' has fewer than the minimum allowed "
        "number of characters."
    )

    @classmethod
    def home_directory_doesnt_exist(cls):
        """
        If an instance's home directory doesn't exist on the users file-
        system, then the associated data & files created by the binary
        will have nowhere to be saved. This will cause issues. This
        method returns the issue for the user in a `FileNotFoundError`.
        """
        return FileNotFoundError(cls._HOME_DIRECTORY_DOESNT_EXIST)

    @classmethod
    def secret_keyword_argument_isnt_a_bool(cls, secret: bool):
        """
        There should be no abiguity when instructing the gpg2 binary to
        do anything related to secret keys. So, if a user passes a non-
        boolean to the ``secret`` keyword argument, then either their
        intention or understanding of the method aren't clear. This
        method returns the issue in a TypeError for the user.
        """
        secret_type = str(type(secret))
        issue = cls._SECRET_KEYWORD_ARGUMENT_ISNT_A_BOOL
        return TypeError(issue.replace("_TYPE_", secret_type))

    @classmethod
    def key_keyword_argument_isnt_a_bool(cls, key: bool):
        """
        There should be no abiguity when instructing the gpg2 binary to
        do anything related to secret keys & signing other keys. So, if
        a user passes a non-boolean to the ``key`` keyword argument,
        then either their intention or understanding of the method
        aren't clear. This method returns the issue in a `TypeError` for
        the user.
        """
        key_type = str(type(key))
        issue = cls._KEY_KEYWORD_ARGUMENT_ISNT_A_BOOL
        return TypeError(issue.replace("_TYPE_", key_type))

    @classmethod
    def inadequate_length_uid_was_given(cls, uid: str):
        """
        An adequate amount of user ID information is needed to retrieve
        or target the correct key in the instance's keyring or on the
        keyserver. Targeting the wrong key can be very problematic.
        This method returns the issue in a `ValueError` for the user.
        """
        issue = cls._INADEQUATE_LENGTH_UID_WAS_GIVEN
        return ValueError(issue.replace("_UID_", uid))

    @classmethod
    def trust_levels_must_be_between_1_and_5(cls):
        """
        The trust levels on keys are only valid when they're integers
        between 1 and 5, inclusively (1, 5). An invalid trust level
        would cause an error. This method returns the issue in a
        `ValueError` for the user.
        """
        return ValueError(cls._TRUST_LEVELS_MUST_BE_BETWEEN_1_AND_5)

    @classmethod
    def uid_wasnt_found_on_the_keyserver(cls, uid: str):
        """
        The user won't be able to use or import a key over the network
        if it isn't found on the keyserver. This method returns the
        issue in a `FileNotFoundError` for the user.
        """
        issue = cls._UID_WASNT_LOCATED_ON_THE_KEYSERVER
        return FileNotFoundError(issue.replace("_UID_", uid))


class GnuPG:
    """
    GnuPG - A linux-specific, small, simple & intuitive wrapper for
    creating, using and managing GnuPG's Ed25519 curve keys. This class
    favors reducing code size & complexity with strong, bias defaults
    over flexibility in the API. It's designed to turn the complex,
    legacy, but powerful GnuPG system into a fun tool to develop with.

    Usage Example:

    gpg = GnuPG(
        username="user3121",
        email="spicy.salad@email.org",
        passphrase="YesAllBeautifulCats",
        executable="/usr/bin/gpg2",
    )
    gpg.gen_key()
    assert gpg.fingerprint in gpg.list_keys()
    run(gpg.network_export(gpg.fingerprint))

    message = "Henlo fren!"
    uid = "my.friends@email.address"

    assert run(gpg.search(uid))
    encrypted_message = run(gpg.auto_encrypt(message, uid=uid, sign=True))
    """

    _HOME_DIRECTORY = Path(__file__).absolute().parent / "gpghome"
    _OPTIONS_PATH = _HOME_DIRECTORY / "gpg2.conf"
    _EXECUTABLE_PATH = Path("/usr/bin/gpg2").absolute()
    _MINIMUM_UID_LENGTH = 6
    _SEARCH_PREFIX = "search?q="
    _KEYSERVER = (
        "http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmba"
        "d.onion"
    )

    def __init__(
        self,
        *,
        username: str,
        email: str,
        passphrase: str,
        torify=False,
        homedir=None,
        options=None,
        executable=None,
    ):
        """
        Initialize an instance intended to create, manage, or represent
        a single key in the local instance GnuPG keyring.
        """
        self._torify = bool(torify)
        self.set_homedir(homedir)
        self.set_options(options)
        self.set_executable(executable)
        self._reset_daemon()
        self.user = User(username, email, passphrase=passphrase)
        self._set_fingerprint(email)
        self._set_network_variables()

    @classmethod
    def _set_permissions_recursively(
        cls, path: Union[Path, str], permissions=0o700
    ):
        """
        Takes a `pathlib.Path` object & recursively sets each sub- file
        & directory's ``permissions``.
        """
        for subpath in path.iterdir():
            os.chmod(subpath, permissions)
            if subpath.is_dir():
                cls._set_permissions_recursively(subpath, permissions)

    def _set_homedir_permissions(self, homedir: Union[Path, str] = None):
        """
        Set safer permissions on the home directory.
        """
        homedir = Path(homedir).absolute() if homedir else self._homedir
        if not homedir.exists():
            raise Issue.home_directory_doesnt_exist()
        os.chmod(homedir, 0o700)
        self._set_permissions_recursively(homedir, 0o700)

    def set_homedir(self, path: Union[Path, str] = None):
        """
        Initialize a home directory for gpg2 data to be saved.
        """
        path = Path(path).absolute() if path else self._HOME_DIRECTORY
        self._homedir = path
        self._set_homedir_permissions()

    def set_options(self, path: Union[Path, str] = None):
        """
        Initialize a path to the gpg2 config file.
        """
        path = Path(path).absolute() if path else self._OPTIONS_PATH
        self._options = path

    def set_executable(self, path: Union[Path, str] = None):
        """
        Initialize a path to the gpg2 executable binary.
        """
        path = Path(path).absolute() if path else self._EXECUTABLE_PATH
        self._executable = path

    @property
    def homedir(self):
        """
        Returns the string home directory where gpg2 data is saved.
        """
        return str(self._homedir)

    @property
    def options(self):
        """
        Returns the string path to the gpg2 config file.
        """
        return str(self._options)

    @property
    def executable(self):
        """
        Returns the string path to the gpg2 executable binary.
        """
        return str(self._executable)

    @property
    def _base_command(self):
        """
        Construct the default command used to call gpg2.
        """
        torify = ["torify"] if self._torify else []
        return torify + [
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

    @property
    def _base_passphrase_command(self):
        """
        Construct the default command used to call gpg2 when a user's
        passphrase is needed.
        """
        return self._base_command + [
            "--pinentry-mode",
            "loopback",
            "--passphrase-fd",
            "0",
        ]

    def _set_fingerprint(self, uid: str):
        """
        Populate ``fingerprint`` attribute for persistent user.
        """
        try:
            self.fingerprint = self.key_fingerprint(uid)
        except:
            self.fingerprint = ""

    @staticmethod
    def _quick_cleanup_for_url(string, *, tokens="\n\t\r\\ "):
        """
        Removes whitespace & problem ``tokens`` from a url ``string``
        as well as trailing slashes, then returns the new string.
        """
        for token in tokens:
            string = string.replace(token, "")
        return string.strip("/")

    def _set_network_variables(
        self,
        *,
        port=Network._PORT,
        tor_port=Network._TOR_PORT,
        keyserver=_KEYSERVER,
        search_prefix=_SEARCH_PREFIX,
    ):
        """
        Set network variables for adaptable implementations.
        """
        self.network = Network(port=port, tor_port=tor_port)
        self._keyserver_host = self._quick_cleanup_for_url(keyserver)
        self._search_prefix = self._quick_cleanup_for_url(search_prefix)

    @property
    def _keyserver(self):
        """
        Autoconstruct keyserver URL with adaptable port number.
        """
        return f"{self._keyserver_host}:{self.network.port}/"

    @property
    def _keyserver_export_api(self):
        """
        Autoconstruct specific keyserver key upload API URL.
        """
        return self._keyserver + "vks/v1/upload"

    @property
    def _keyserver_verify_api(self):
        """
        Autoconstruct specific keyserver key verification API URL.
        """
        return self._keyserver + "vks/v1/request-verify"

    @property
    def _searchserver(self):
        """
        Autoconstruct specific keyserver search URL.
        """
        return self._keyserver + self._search_prefix

    async def _raw_search(self, uid: str):
        """
        Returns keyserver HTML of the search matching ``uid``.
        """
        if len(uid) < self._MINIMUM_UID_LENGTH:
            raise Issue.inadequate_length_uid_was_given(uid)
        uid = uid.replace("@", "%40").replace(" ", "%20")
        url = self._searchserver + uid
        print(f"querying: {url}")
        return await self.network.get(url)

    async def search(self, uid: str):
        """
        Returns keyserver URL of the key matching ``uid``.
        """
        html = await self._raw_search(uid)
        if "We found an entry" not in html:
            return ""
        url = self._keyserver_host
        html = html[html.find(url) :]
        return html[: html.find(">") - 1]

    def encode_command(
        self, *options: Iterable[str], with_passphrase=False, manual=False
    ):
        """
        Autoformats gpg2 commands soley from additional options.
        """
        if with_passphrase:
            return self._base_passphrase_command + [*options]
        elif not manual:
            return self._base_command + [*options]
        else:
            cmd = self._base_command + [*options]
            cmd.remove("--yes")
            cmd.remove("--batch")
            cmd.remove("--no-tty")
            return cmd

    def encode_inputs(self, *inputs: Iterable[str]):
        """
        Prepares ``*inputs`` for the `input` keyword-argument to the
        `subprocess.check_output` method.
        """
        return ("\n".join(inputs) + "\n").encode()

    def read_output(self, command: Iterable[str], inputs=b"", **kw):
        """
        Quotes terminal escape characters & runs user commands.
        """
        with Terminal(if_exception=Error.no_permission) as terminal:
            terminal.bus.kw = kw
            terminal.bus.inputs = inputs
            terminal.bus.command = command
            return terminal.enter(command, inputs, **kw)

    def _reset_daemon(self):
        """
        Resets the gpg-agent daemon.
        """
        kill_command = [
            "gpgconf", "--homedir", self.homedir, "--kill", "gpg-agent"
        ]
        Terminal.enter(kill_command)
        start_command = ["gpg-agent", "--homedir", self.homedir, "--daemon"]
        Terminal.enter(start_command)

    def _add_subkeys(self, uid: str):
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
        output = Terminal.enter(command, inputs, stderr=STDOUT)
        self.fingerprint = output.strip().split("\n")[-1][-40:]
        self._add_subkeys(self.fingerprint)

    def _raw_packets(self, target: str):
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
        with Terminal(if_exception=Error.secret_packets) as terminal:
            return terminal.enter(command, inputs, stderr=STDOUT)

    def _list_packets(self, target: str):
        """
        Returns OpenPGP metadata from ``target`` in list format.
        """
        with Terminal(if_exception=Error.invalid_pgp_packets) as terminal:
            terminal.bus.target = target
            terminal.bus.packets = self._raw_packets(target)
        return [
            packet.strip().split("\n")
            for packet in terminal.bus.packets.strip().split("\n\t")
        ]

    def _packet_fingerprint(self, target: str):
        """
        Returns the sender's key fingerprint scraped from some ``target``
        OpenPGP data.
        """
        with Terminal(if_exception=Error.invalid_pgp_packets) as terminal:
            bus = terminal.bus
            bus.target = target
            bus.packets = self._raw_packets(target)
        packets = bus.packets.replace("key ID", "keyid").replace(")", "")
        if "(issuer fpr" in packets:
            size = slice(-40, None)
            sentinel = "(issuer fpr"
        else:
            sentinel = "keyid "
            size = slice(-16, None)
        for packet in packets.split("\n\t"):
            if sentinel in packet:
                return packet[size]

    def _raw_list_keys(self, uid="", secret=False):
        """
        Returns the terminal output of the --list-keys ``uid`` option,
        or `--list-secret-keys` if ``secret`` == True.
        """
        if secret.__class__ != bool:  # avoid truthiness
            raise Issue.secret_keyword_argument_isnt_a_bool(secret)
        option = "--list-secret-keys" if secret else "--list-keys"
        options = (option, uid) if uid else (option,)
        command = self.encode_command(*options)
        with Terminal(if_exception=Error.cannot_list_key) as terminal:
            terminal.bus.uid = uid
            terminal.bus.secret = secret
            return terminal.enter(command)

    def _format_list_keys(self, raw_listed_keys: str, secret: bool):
        """
        Returns a dict of fingerprints & email addresses scraped from
        the terminal output of the `--list-keys` option, or `--list-
        secret-keys` if ``secret`` == True.
        """
        sentinel = "sec" if secret else "pub"
        fingerprints = (
            part[part.find("\nuid") - 40 : part.find("\nuid")]
            for part in raw_listed_keys.split(f"\n{sentinel} ")
            if "\nuid" in part
        )
        return {
            fingerprint: self.key_email(fingerprint)
            for fingerprint in fingerprints
        }

    def list_keys(self, uid="", *, secret=False):
        """
        Returns a dict of fingerprints & email addresses of all keys in
        the instance's keyring, or optionally the key matching ``uid``.
        """
        return self._format_list_keys(
            self._raw_list_keys(uid, secret=secret), secret=secret
        )

    def key_email(self, uid: str):
        """
        Returns the email address on the key matching ``uid``.
        """
        if len(uid) < self._MINIMUM_UID_LENGTH:
            raise Issue.inadequate_length_uid_was_given(uid)
        key_metadata = self._raw_list_keys(uid).replace(" ", "")
        for line in key_metadata.split("\n"):
            if "@" not in line or "uid" not in line:
                continue
            line = line[-line[::-1].find("]") :]
            if "<" in line:
                line = line[-line[::-1].find("<") : -1]
            return line

    def key_fingerprint(self, uid: str):
        """
        Returns the fingerprint of the key matching ``uid``.
        """
        if len(uid) < self._MINIMUM_UID_LENGTH:
            raise Issue.inadequate_length_uid_was_given(uid)
        return next(iter(self.list_keys(uid)))

    def key_trust(self, uid: str):
        """
        Returns the current trust level of the key matching ``uid``.
        """
        if len(uid) < self._MINIMUM_UID_LENGTH:
            raise Issue.inadequate_length_uid_was_given(uid)
        key = self._raw_list_keys(uid).replace(" ", "")
        trust = key[key.find("\nuid[") + 5 :]
        return trust[: trust.find("]")]

    def set_key_trust(self, uid: str, level=5):
        """
        Sets the trust ``level`` of a key in the instance's keyring
        which matches ``uid``.
        """
        uid = self.key_fingerprint(uid)
        level = int(level)
        if 1 > level or level > 5:
            raise Issue.trust_levels_must_be_between_1_and_5()
        command = self.encode_command(
            "--edit-key", "--command-fd", "0", uid
        )
        inputs = self.encode_inputs("trust", str(level), "y", "save")
        Terminal.enter(command, inputs)

    def delete(self, uid: str):
        """
        Deletes secret & public key matching ``uid`` from the instance's
        keyring.
        """
        uid = self.key_fingerprint(uid)  # avoid non-fingerprint uid crash
        if uid in self.list_keys(secret=True):
            command = self.encode_command(
                "--command-fd", "0", "--delete-secret-keys", uid
            )
            inputs = self.encode_inputs("y", "y")
            Terminal.enter(command, inputs)
        command = self.encode_command(
            "--command-fd", "0", "--delete-key", uid
        )
        inputs = self.encode_inputs("y")
        Terminal.enter(command, inputs)

    def revoke(self, uid: str):
        """
        Generates & imports a revocation cert for a key matching ``uid``,
        then returns the revoked key.
        """
        uid = self.key_fingerprint(uid)
        command = self.encode_command(
            "--command-fd", "0", "--gen-revoke", uid, with_passphrase=True
        )
        command.remove("--batch")
        inputs = self.encode_inputs(
            self.user.passphrase, "y", "0", " ", "y"
        )
        revocation_cert = self.read_output(command, inputs)
        self.text_import(revocation_cert)
        return self.text_export(uid)

    def encrypt(self, message: str, uid: str, *, sign=True, local_user=""):
        """
        Encrypts ``message`` to the key matching ``uid`` & signs it with
        a key matching the ``local_user`` UID. ``local_user`` defaults
        to the instance's key. Optionally, if ``sign`` == False, the
        ``message`` won't be signed.
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
        self, message: str, uid: str, *, sign=True, local_user=""
    ):
        """
        Queries the keyserver before encryption if the recipient's key
        matching ``uid`` isn't in the instance's keyring.
        """
        try:
            return self.encrypt(
                message, uid, sign=sign, local_user=local_user
            )
        except LookupError as error:
            await self.network_import(error.uid)
            return self.encrypt(
                message, error.uid, sign=sign, local_user=local_user
            )

    def decrypt(self, message: str, *, local_user=""):
        """
        Auto-detects the correct key from the instance's keyring to
        decrypt ``message``.
        """
        self._reset_daemon()
        uid = self._packet_fingerprint(message)
        uid = self.key_fingerprint(uid)
        command = self.encode_command(
            "--local-user",
            local_user if local_user else self.fingerprint,
            "-d",
            with_passphrase=True,
        )
        inputs = self.encode_inputs(self.user.passphrase, message)
        with Terminal(if_exception=Error.no_signature_key) as terminal:
            terminal.bus.uid = uid
            terminal.bus.inputs = inputs
            terminal.bus.command = command
            terminal.bus.keys = self.list_keys
            return terminal.enter(command, inputs)

    async def auto_decrypt(self, message: str, *, local_user=""):
        """
        Queries the keyserver before decryption if the key which signed
        ``message`` isn't in the instance's keyring.
        """
        try:
            return self.decrypt(message, local_user=local_user)
        except LookupError as error:
            await self.network_import(error.uid)
            return self.decrypt(message, local_user=local_user)

    def sign(self, target="", *, key=False, local_user=""):
        """
        Signs the ``target`` message using a key which matches the
        ``local_user`` UID, but defaults to the instance's key.
        Optionally, if ``key`` == True, this method signs a key in the
        instance's keyring matching the ``target`` UID.
        """
        self._reset_daemon()
        if key.__class__ != bool:  # avoid truthiness
            raise Issue.key_keyword_argument_isnt_a_bool(key)
        elif key:
            command = self.encode_command(
                "--local-user",
                local_user if local_user else self.fingerprint,
                "--sign-key",
                target,
                with_passphrase=True,
            )
            inputs = self.encode_inputs(self.user.passphrase)
            self.read_output(command, inputs)
        else:
            command = self.encode_command(
                "--local-user",
                local_user if local_user else self.fingerprint,
                "-as",
                with_passphrase=True,
            )
            inputs = self.encode_inputs(self.user.passphrase, target)[:-1]
            return self.read_output(command, inputs)

    def verify(self, message: str):
        """
        Verifies the signed ``message`` if the corresponding public key
        is in the instance's keyring.
        """
        uid = self._packet_fingerprint(message)
        uid = self.key_fingerprint(uid)
        command = self.encode_command("--verify")
        inputs = self.encode_inputs(message)
        with Terminal(if_exception=Error.unverifiable_message) as terminal:
            terminal.bus.uid = uid
            terminal.enter(command, inputs)
            return True

    async def auto_verify(self, message: str):
        """
        Queries the keyserver before verifying the ``message`` if its
        signature key isn't in the instance's keyring.
        """
        try:
            return self.verify(message)
        except LookupError as error:
            await self.network_import(error.uid)
            return self.verify(message)

    async def network_import(self, uid: str):
        """
        Imports the key matching ``uid`` from the keyserver.
        """
        key_url = await self.search(uid)
        if not key_url:
            raise Issue.uid_wasnt_found_on_the_keyserver(uid)
        print(f"key location: {key_url}")
        key = await self.network.get(key_url)
        print(f"downloaded:\n{key}")
        return self.text_import(key)

    def file_import(self, path: Union[Path, str]):
        """
        Imports a key from the file located at ``path``.
        """
        with open(path, "r") as keyfile:
            self.text_import(keyfile.read())

    def text_import(self, key: str):
        """
        Imports the ``key`` string into the instance's keyring.
        """
        inputs = self.encode_inputs(key)
        command = self.encode_command("--import")
        with Terminal(if_exception=Error.key_isnt_importable) as terminal:
            terminal.bus.key = key
            terminal.bus.uid = self._packet_fingerprint(key)
            terminal.enter(command, inputs, stderr=STDOUT)

    async def _raw_api_export(self, uid: str):
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

    async def _raw_api_verify(self, payload: str):
        """
        Prompts the keyserver to verify the list of email addresses in
        ``payload``["addresses"] with the api_token in ``payload``["token"].
        The keyserver then sends a confirmation email asking for consent
        to publish the UID information with the key that was uploaded.
        """
        url = self._keyserver_verify_api
        print(f"sending verification to: {url}")
        return await self.network.post(url, json=payload)

    async def network_export(self, uid: str):
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

    def file_export(self, path: Union[Path, str], uid: str, *, secret=False):
        """
        Exports the public key matching ``uid`` to the ``path`` directory.
        If ``secret`` == True then exports the secret key that matches
        ``uid``.
        """
        key = self.text_export(uid, secret=secret)
        uid = self.key_fingerprint(uid)
        filename = Path(path).absolute() / (uid + ".asc")
        with open(filename, "w+") as keyfile:
            keyfile.write(key)

    def text_export(self, uid: str, *, secret=False):
        """
        Returns a public key string that matches ``uid``. Optionally,
        returns the secret key as a string that matches ``uid`` if
        ``secret`` == True.
        """
        uid = self.key_fingerprint(uid)
        if secret.__class__ != bool:  # avoid truthiness
            raise Issue.secret_keyword_argument_isnt_a_bool(secret)
        elif secret:
            command = self.encode_command(
                "-a", "--export-secret-keys", uid, with_passphrase=True
            )
            inputs = self.encode_inputs(self.user.passphrase)
            return self.read_output(command, inputs)
        else:
            command = self.encode_command("-a", "--export", uid)
            return Terminal.enter(command)

