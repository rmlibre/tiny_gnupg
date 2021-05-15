# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#


from setuptools import setup, find_packages
from tiny_gnupg import __package__, __version__, __license__


description = (
    "tiny_gnupg - A small-as-possible solution for handling GnuPG "
    "ed25519 ECC keys."
)


with open("PREADME.rst", "r") as preadme:
    long_description = preadme.read()


with open("CHANGES.rst", "r") as changelog:
    long_description += changelog.read()


with open("README.rst", "w+") as readme:
    readme.write(long_description)


setup(
    name=__package__,
    license=__license__,
    version=__version__,
    description=description,
    long_description=long_description,
    long_description_content_type="text/x-rst",
    author="Gonzo Investigative Journalism Agency, LLC",
    author_email="gonzo.development@protonmail.ch",
    maintainer="Gonzo Investigative Journalism Agency, LLC",
    maintainer_email="gonzo.development@protonmail.ch",
    classifiers=[
        "Framework :: AsyncIO",
        "Natural Language :: English",
        "Development Status :: 4 - Beta",
        "Topic :: Internet",
        "Topic :: Utilities",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Topic :: Adaptive Technologies",
        "Topic :: Communications",
        "Topic :: Communications :: Email",
        "Topic :: Security :: Cryptography",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    keywords=" ".join(
        [
            "gpg gpg2 gnupg gnupg2",
            "pgp openpgp org",
            "await async asyncio aiohttp",
            "clean simple code",
            "elliptic curve crypto",
            "ed25519 25519",
            "wrapper automation adapter-pattern",
            "tor anonymous anonymity",
            "security appsec opsec infosec",
            "beta testing",
            "communications comms message messages",
            "encrypt encryption authentication",
            "decrypt decryption verify verification",
            "signature signatures",
            "SOCKSv5 socks5 proxy",
            "web key keys keyserver",
        ]
    ),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "aiohttp_socks",
        "asyncio_contextmanager",
    ],
    tests_require=["pytest"],
    packages=find_packages(),
) if __name__ == "__main__" else 0

