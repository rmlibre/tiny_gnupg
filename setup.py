# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#

from setuptools import setup, find_packages

description = """
tiny_gnupg - A small-as-possible solution for handling GnuPG ed25519 ECC keys.
""".replace("\n", "")

with open("PREADME.rst", "r") as preadme:
    long_description = preadme.read()

with open("CHANGES.rst", "r") as changelog:
    long_description += f"\n\n\n\n{changelog.read()}"

with open("README.rst", "w+") as readme:
    readme.write(long_description)

setup(
    name="tiny_gnupg",
    license="GPLv3",
    version="0.5.6",
    description=description,
    long_description=long_description,
    url="https://github.com/rmlibre/tiny_gnupg",
    author="Gonzo Investigatory News Agency, LLC",
    author_email="gonzo.development@protonmail.ch",
    maintainer="Gonzo Investigatory News Agency, LLC",
    maintainer_email="gonzo.development@protonmail.ch",
    classifiers=[
        "Topic :: Utilities",
        "Framework :: AsyncIO",
        "Natural Language :: English",
        "Development Status :: 4 - Beta",
        "Topic :: Internet",
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
            "gpg",
            "gpg2",
            "gnupg",
            "gnupg2",
            "await",
            "async",
            "asyncio",
            "clean",
            "simple code",
            "tor",
            "elliptic",
            "curve",
            "crypto",
            "ed25519",
            "wrapper",
            "anonymous",
            "anonymity",
            "security",
            "beta testing",
            "automation",
            "adapter-pattern",
            "communications",
            "SOCKSv5",
            "socks5",
            "web",
        ]
    ),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "aiofiles",
        "aiohttp_socks",
        "asyncio_contextmanager",
    ],
    tests_require=["pytest"],
    packages=find_packages(),
) if __name__ == "__main__" else 0

