# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado <rmlibre@riseup.net>
# All rights reserved.
#

from setuptools import setup, find_packages

description = """
tiny_gnupg - A small-as-possible solution for handling GnuPG ECC keys.
""".replace("\n", "")

with open("README.rst", "r") as readme:
    long_description = readme.read()

setup(
    name="tiny_gnupg",
    license="GPLv3",
    version="0.3.6",
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
    include_package_data=True,
    install_requires=[
        "pathlib",
        "aiohttp",
        "aiofiles",
        "asyncio_contextmanager",
        "aiohttp_socks",
    ],
    tests_require=["pytest"],
    packages=find_packages(),
)
