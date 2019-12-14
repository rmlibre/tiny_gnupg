# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#

__all__ = ["GnuPG"]

import json
import aiofiles
from shlex import quote
from pathlib import Path
from aiohttp import ClientSession
from subprocess import check_output
from aiocontext import async_contextmanager
from aiohttp_socks import SocksConnector, SocksVer


HOME_PATH = Path(__file__).parent / "gpghome"


class GnuPG:
    def __init__(self, username="", email="", passphrase=""):
        self.set_homedir()
        self.email = email
        self.username = username
        self.passphrase = passphrase
        self.set_fingerprint(email)
        self.set_network_variables()

    def set_homedir(self, path=HOME_PATH):
        self.home = self.format_homedir(path)
        self.executable = self.home + "/gpg2"
        command = ["chmod", "-R", "700", self.home]
        return self.read_output(command)

    def format_homedir(self, path=HOME_PATH):
        return str(Path(path).absolute())

    def set_fingerprint(self, uid=""):
        try:
            self.fingerprint = self.key_fingerprint(uid)
        except:
            self.fingerprint = ""

    def set_network_variables(
        self,
        port=80,
        tor_port=9050,
        keyserver="http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion",
        search="search?q=",
    ):
        self.port = port
        self.tor_port = tor_port
        self._keyserver = keyserver
        self._search_string = search
        self._connector = SocksConnector
        self._session = ClientSession

    @property
    def keyserver(self):
        return f"{self._keyserver}:{self.port}/"

    @property
    def keyserver_export_api(self):
        return self.keyserver + "vks/v1/upload"

    @property
    def keyserver_verify_api(self):
        return self.keyserver + "vks/v1/request-verify"

    @property
    def searchserver(self):
        return f"{self.keyserver}{self._search_string}"

    @property
    def connector(self):
        return self._connector(
            socks_ver=SocksVer.SOCKS5,
            host="127.0.0.1",
            port=self.tor_port,
            rdns=True,
        )

    @property
    def session(self):
        return self._session(connector=self.connector)

    @async_contextmanager
    async def network_get(self, url="", **kw):
        try:
            session = await self.session.__aenter__()
            yield await session.get(url, **kw)
        finally:
            await session.close()

    @async_contextmanager
    async def network_post(self, url="", **kw):
        try:
            session = await self.session.__aenter__()
            yield await session.post(url, **kw)
        finally:
            await session.close()

    async def get(self, url="", **kw):
        async with self.network_get(url, **kw) as response:
            return await response.text()

    async def post(self, url="", **kw):
        async with self.network_post(url, **kw) as response:
            return await response.text()

    def command(self, *options, with_passphrase=False):
        if with_passphrase:
            return [
                self.executable,
                "--yes",
                "--batch",
                "--quiet",
                "--homedir",
                self.home,
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                *options,
            ]
        else:
            return [
                self.executable,
                "--yes",
                "--batch",
                "--quiet",
                "--homedir",
                self.home,
                *options,
            ]

    def encode_inputs(self, *inputs):
        return ("\n".join(inputs) + "\n").encode()

    def read_output(self, command=(), inputs=b"", shell=False):
        return check_output(
            [quote(part) for part in command],
            input=inputs,
            shell=shell,
        ).decode()

    def gen_key(self):
        command = [
            self.executable,
            "--yes",
            "--quiet",
            "--homedir",
            self.home,
            "--pinentry-mode",
            "loopback",
            "--expert",
            "--full-gen-key",
            "--with-colons",
            "--command-fd",
            "0",
            "--status-fd",
            "1",
            "--passphrase-fd",
            "0",
        ]
        inputs = self.encode_inputs(
            self.passphrase,
            "11",
            "S",
            "Q",
            "1",
            "0",
            "y",
            self.username,
            self.email,
            "There's safety in numbers.",
            "O",
        )
        output = self.read_output(command, inputs)
        self.fingerprint = output.strip().split("\n")[-1][-40:]
        return self.add_subkeys(self.fingerprint)

    def add_subkeys(self, uid=""):
        command = self.command(
            "--command-fd",
            "0",
            "--edit-key",
            "--expert",
            uid,
            with_passphrase=True,
        )
        inputs = self.encode_inputs(
            self.passphrase,
            "addkey",
            "10",
            "1",
            "0",
            "addkey",
            "11",
            "A",
            "S",
            "Q",
            "1",
            "0",
            "addkey",
            "12",
            "1",
            "0",
            "save",
        )
        return self.read_output(command, inputs)

    def delete(self, uid=""):
        uid = self.key_fingerprint(uid)
        try:
            command = self.command(
                "--command-fd",
                "0",
                "--delete-secret-keys",
                uid,
            )
            inputs = self.encode_inputs("y", "y")
            print(self.read_output(command, inputs))
        except Exception as e:
            print(e)
        command = self.command("--command-fd", "0", "--delete-key", uid)
        inputs = self.encode_inputs("y")
        return self.read_output(command, inputs)

    def trust(self, uid="", level=5):
        level = str(int(level))
        if not 1 <= int(level) <= 5:
            raise ValueError("Trust levels must be between 1 and 5.")
        command = self.command("--edit-key", "--command-fd", "0", uid)
        inputs = self.encode_inputs("trust", level, "y", "save")
        return self.read_output(command, inputs)

    def encrypt(self, message="", uid="", sign=True, local_user=""):
        command = self.command(
            "--command-fd",
            "0",
            "--local-user",
            local_user if local_user else self.fingerprint,
            "-esar" if sign else "-ear",
            uid,
            with_passphrase=True,
        )
        command.remove("--batch")  # avoid crash with untrusted keys
        if self.key_trust(uid) != "ultimate":
            inputs = self.encode_inputs(self.passphrase, "y", message)
        else:
            inputs = self.encode_inputs(self.passphrase, message)
        return self.read_output(command, inputs)

    def decrypt(self, message=""):
        command = self.command("-d", with_passphrase=True)
        inputs = self.encode_inputs(self.passphrase, message)
        return self.read_output(command, inputs)

    def sign(self, message="", local_user=""):
        command = self.command(
            "--local-user",
            local_user if local_user else self.fingerprint,
            "-as",
            with_passphrase=True,
        )
        inputs = self.encode_inputs(self.passphrase, message)
        return self.read_output(command, inputs)

    def verify(self, message=""):
        command = self.command("--verify")
        inputs = self.encode_inputs(message)
        return self.read_output(command, inputs)

    def raw_list_keys(self, uid=""):
        if uid:
            command = self.command(f"--list-keys", uid)
        else:
            command = self.command(f"--list-keys")
        return self.read_output(command)

    def format_list_keys(self, raw_list_keys_terminal_output):
        keys = raw_list_keys_terminal_output.split("\npub ")
        fingerprints = [
            part[part.find("\nuid") - 40 : part.find("\nuid")]
            for part in keys
            if "\nuid" in part
        ]
        emails = [
            self.key_email(fingerprint)
            for fingerprint in fingerprints
        ]
        return dict(zip(fingerprints, emails))

    def list_keys(self, uid=""):
        return self.format_list_keys(self.raw_list_keys(uid))

    def key_email(self, uid=""):
        parts = self.raw_list_keys(uid).replace(" ", "")
        for part in parts.split("\nuid"):
            if "@" in part and "]" in part:
                part = part[part.find("]") + 1 :]
                if "<" in part and ">" in part:
                    part = part[part.find("<") + 1 : part.find(">")]
                return part

    def key_fingerprint(self, uid=""):
        key = self.list_keys(uid)
        return next(iter(key))

    def key_trust(self, uid=""):
        key = self.raw_list_keys(uid).replace(" ", "")
        trust = key[key.find("\nuid[") + 5 :]
        return trust[: trust.find("]")].strip()

    def reset_daemon(self):
        command = [
            "gpgconf",
            "--homedir",
            self.home,
            "--kill",
            "gpg-agent",
        ]
        kill_output = self.read_output(command)
        command = ["gpg-agent", "--homedir", self.home, "--daemon"]
        reset_output = self.read_output(command)
        return kill_output, reset_output

    async def raw_search(self, query=""):
        url = f"{self.searchserver}{query}"
        print(f"querying: {url}")
        return await self.get(url)

    async def search(self, query=""):
        query = query.replace("@", "%40")
        response = await self.raw_search(query)
        if "We found an entry" not in response:
            return ""
        part = response[response.find(f">{self._keyserver}") + 1 :]
        return part[: part.find("</a>")]

    async def network_import(self, uid=""):
        key_url = await self.search(uid)
        if not key_url:
            raise FileNotFoundError("No key found on server.")
        print(f"key location: {key_url}")
        key = await self.get(key_url)
        print(f"downloaded:\n{key}")
        return self.text_import(key)

    async def file_import(self, path="", mode="r"):
        async with aiofiles.open(path, mode) as keyfile:
            key = await keyfile.read()
        return self.text_import(key)

    def text_import(self, key=""):
        command_bugfix = self.command(
            "--import-options", "import-drop-uids", "--import"
        )
        # "--import-options", "import-drop-uids" needed to allow import
        # of keys without uids from Hagrid-like keyservers.
        command = self.command("--import")
        inputs = self.encode_inputs(key)
        try:
            return self.read_output(command_bugfix, inputs)
        except:
            return self.read_output(command, inputs)

    async def raw_api_export(self, uid=""):
        key = self.text_export(uid)
        url = self.keyserver_export_api
        print(f"contacting: {url}")
        print(f"exporting:\n{key}")
        payload = {"keytext": key}
        return await self.post(url, json=payload)

    async def raw_api_verify(self, payload=""):
        url = self.keyserver_verify_api
        print(f"sending verification to: {url}")
        return await self.post(url, json=payload)

    async def network_export(self, uid=""):
        response = json.loads(await self.raw_api_export(uid))
        payload = {
            "addresses": [self.key_email(uid)],
            "token": response["token"],
        }
        response = json.loads(await self.raw_api_verify(payload))
        print(f"check {payload['addresses'][0]} for confirmation.")
        return response

    async def file_export(
        self, path="", uid="", mode="w+", *, secret=False
    ):
        key = self.text_export(uid, secret=secret)
        fingerprint = self.key_fingerprint(uid)
        filename = Path(path) / (fingerprint + ".asc")
        async with aiofiles.open(filename, mode) as keyfile:
            return await keyfile.write(key)

    def text_export(self, uid="", *, secret=False):
        if secret == True:  # make strictly True, not just truthy
            command = self.command(
                "-a", "--export-secret-keys", uid, with_passphrase=True
            )
            inputs = self.encode_inputs(self.passphrase)
            return self.read_output(command, inputs)
        else:
            command = self.command("-a", f"--export", uid)
            return self.read_output(command)
