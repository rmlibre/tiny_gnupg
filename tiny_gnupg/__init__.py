# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2021 Gonzo Investigative Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2021 Richard Machado, <rmlibre@riseup.net>
# All rights reserved.
#


__all__ = [
    "GnuPG",
    "BaseGnuPG",
    "User",
    "GnuPGConfig",
    "Keyserver",
    "Network",
    "Terminal",
    "run",
]


__version__ = "0.9.0"


__license__ = "GPLv3"


__doc__ = (
    "tiny_gnupg - a small-as-possible solution for handling GnuPG "
    "ed25519 ECC keys."
)


from .tiny_gnupg import *

