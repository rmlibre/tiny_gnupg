# This file is part of tiny_gnupg, a small-as-possible solution for
# handling GnuPG ed25519 ECC keys.
#
# Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
# Copyright © 2019-2020 Gonzo Investigatory Journalism Agency, LLC
#             <gonzo.development@protonmail.ch>
#           © 2019-2020 Richard Machado, <rmlibre@riseup.net>
# All rights reserved.
#

__version__ = "0.5.7"

from .tiny_gnupg import GnuPG, run, __all__
