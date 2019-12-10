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


class GnuPG:
    def __init__(self, username="", email="", passphrase=""):
        self.set_homedir()
        self.email = email
        self.username = username
        self.passphrase = passphrase
        self.fingerprint = ""
        self.set_network_variables()

    def set_homedir(self, path="gpghome"):
        self.home = self.format_homedir(path)
        self.executable = self.home + "/gpg2"

    def format_homedir(self, path="gpghome"):
        return Path(path).absolute().as_uri().replace("file://", "")

    def set_network_variables(
        self,
        port=80,
        tor_port=9050,
        keyserver="http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion/",
        searchserver="http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion/search?q=",
    ):
        self.port = port
        self.tor_port = tor_port
        self.keyserver = keyserver
        self.searchserver = searchserver
        self._connector = SocksConnector
        self._session = ClientSession

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

    def base_command(self, with_passphrase=False):
        if with_passphrase:
            return [
                self.executable,
                "--homedir",
                self.home,
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
            ]
        else:
            return [
                self.executable,
                "--homedir",
                self.home,
            ]

    def command(self, *options, with_passphrase=False):
        return (
            self.base_command(with_passphrase)
            + [quote(option) for option in options]
        )

    def encode_inputs(self, *inputs):
        return ("\n".join(inputs) + "\n").encode()

    def read_output(self, command=None, inputs=b"", shell=False):
        return check_output(command, input=inputs, shell=shell).decode()

    def gen_key(self, main_key=True):
        command = [
            self.executable,
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
            "9",
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

    def encrypt(self, message="", uid=""):
        command = self.command("-esar", uid, with_passphrase=True)
        inputs = self.encode_inputs(self.passphrase, message)
        return self.read_output(command, inputs)

    def decrypt(self, message=""):
        command = self.command("-d", with_passphrase=True)
        inputs = self.encode_inputs(self.passphrase, message)
        return self.read_output(command, inputs)

    def raw_list_keys(self, uid=""):
        if uid:
            command = self.command("--list-keys", uid)
        else:
            command = self.command("--list-keys")
        return self.read_output(command)

    def list_keys(self, uid=""):
        return self.format_list_keys(self.raw_list_keys(uid))

    def format_list_keys(self, raw_list_keys_terminal_output):
        keys = raw_list_keys_terminal_output.split("pub")
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

    def key_email(self, uid=""):
        key = self.raw_list_keys(uid)
        return key[key.find(" <") + 2 : key.find(">")]

    def key_fingerprint(self, uid=""):
        key = self.list_keys(uid)
        return next(iter(key))

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
        async with self.network_get(url) as response:
            return await response.text()

    async def search(self, query=""):
        query = query.replace("@", "%40")
        response = await self.raw_search(query)
        if "We found an entry" not in response:
            return ""
        part = response[response.find(f">{self.keyserver}") + 1:]
        return part[: part.find("</a>")]

    async def network_import(self, uid=""):
        id_link = await self.search(uid)
        if not id_link:
            raise FileNotFoundError("No key found on server.")
        print(f"key location: {id_link}")
        async with self.network_get(id_link) as response:
            key = await response.text()
        if not key:
            raise IOError("Failure to download key from server.")
        print(f"downloaded:\n{key}")
        return self.text_import(key)

    async def file_import(self, filename="", mode="r"):
        async with aiofiles.open(filename, mode) as keyfile:
            key = keyfile.read()
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

    async def raw_network_export(self, uid=""):
        key = self.text_export(uid)
        url = self.keyserver + "vks/v1/upload"
        print(f"contacting: {url}")
        print(f"exporting:\n{key}")
        payload = {"keytext": key}
        async with self.network_post(url, json=payload) as response:
            return await response.text()

    async def raw_network_verify(self, payload=""):
        url = self.keyserver + "vks/v1/request-verify"
        print(f"sending verification to: {url}")
        async with self.network_post(url, json=payload) as response:
            return await response.text()

    async def network_export(self, uid=""):
        response = json.loads(await self.raw_network_export(uid))
        payload = {
            "addresses": [self.key_email(uid)],
            "token": response["token"],
        }
        response = json.loads(await self.raw_network_verify(payload))
        print(f"check {payload['addresses']} for confirmation.")
        return response

    async def file_export(self, path="", uid="", mode="w+"):
        key = self.text_export(uid)
        fingerprint = self.key_fingerprint(uid)
        filename = Path(path) / (fingerprint + ".asc")
        async with aiofiles.open(filename, mode) as keyfile:
            return await keyfile.write(key)

    def text_export(self, uid=""):
        command = self.command("-a", "--export", uid)
        return self.read_output(command)

