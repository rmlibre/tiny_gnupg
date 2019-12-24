
``Known Issues``
=================

-  Because of Debian `bug #930665`_, & related GnuPG `bug #T4393`_,
   importing keys from the default keyserver `keys.openpgp.org`_ doesn’t
   work automatically on all systems. Not without email confirmation, at
   least. That’s because the keyserver will not publish uid information
   attached to a key before a user confirms access to the email address
   assigned to the uploaded key. And, because GnuPG folks are still
   holding up the merging, & back-porting, of patches that would allow
   GnuPG to automatically handle keys without uids gracefully. This
   effects the ``network_import()`` method specifically, but also the
   ``text_import()`` & ``file_import()`` methods, if they happen to be
   passed a key or filename argument which refers to a key without uid
   information. The gpg2 binary in this package can be replaced manually
   if a user’s system has access to a patched version.
-  Because of GnuPG `bug #T3065`_, & related `bug #1788190`_, the
   ``--keyserver`` & ``--keyserver-options http-proxy`` options won’t
   work with onion addresses, & they cause a crash if a keyserver
   lookup is attempted. This is not entirely an issue for us since we
   don’t use gnupg’s networking interface. In fact, we set these
   environment variables anyway to crash on purpose if gnupg tries to
   make a network connection. And in case the bug ever gets fixed (it
   won’t), or by accident the options do work in the future, then a tor
   SOCKSv5 connection will be used instead of a raw connection.
-  This program may only be reliably compatible with keys that are also
   created with this program. That’s because our terminal parsing is
   reliant on specific metadata to be similar across all encountered
   keys. It seems most keys have successfully been parsed with recent
   updates, though more testing is needed.
-  The tests don’t currently work when a tester’s system has a system
   installation of tiny_gnupg, & the tests are being run from a local
   git repo directory. That’s because the tests import tiny_gnupg, but
   if the program is installed in the system, then python will get
   confused about which keyring to use during the tests. This will lead
   to crashes & failed tests. Git clone testers probably have to run
   the test script closer to their system installation, one directory up
   & into a tests folder. Or pip uninstall tiny_gnupg. OR, send a pull
   request with an import fix.
-  Currently, the package is part synchronous, & part asynchronous.
   This is not ideal, so a decision has to be made: either to stay mixed
   style, or choose one consistent style.
-  We’re still in unstable beta & have to build out our test suite.
   Contributions welcome.

.. _bug #930665: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=930665
.. _bug #T4393: https://dev.gnupg.org/T4393
.. _keys.openpgp.org: https://keys.openpgp.org/
.. _bug #T3065: https://dev.gnupg.org/T3065#111023
.. _bug #1788190: https://bugs.launchpad.net/ubuntu/+source/gnupg2/+bug/1788190




``Changelog``
=============


Changes for version 0.5.6
=========================

Minor Changes
-------------

-  Added newly developed ``auto_decrypt()`` & ``auto_encrypt()`` methods
   to the ``README.rst`` tutorial.
-  Allow keyserver queries with spaces by replacing ``" "`` with url
   encoding ``"%20"``.
-  ``packet_fingerprint(target="")`` & ``list_packets(target="")`` methods
   now raise ``TypeError`` when ``target`` is clearly not OpenPGP data.
-  Tests added to account for new error handling in ``tiny_gnupg.py``.


Major Changes
-------------

-  ``--no-tty`` seems to keep most of the noise from terminal output while
   also displaying important banner information. For instance, signature
   verification still produces detailed signature information. Because it
   automatically seems to behave as desired, it's here to stay.




Changes for version 0.5.5
=========================

Minor Changes
-------------

-  Added to Known Issues. Our package can't build on Github (Or most any
   CI service) for many reasons related their build environments using
   Docker & an issue in GnuPG itself.
-  Removed Above known issue as a fix was found for using the Github CI
   tool.
-  Added ``_home``, ``_executable``, & ``_options`` attributes which
   store the ``pathlib.Path.absolute()`` representation of the associated
   files & directories.
-  Added ``options`` attribute with is the str value of the ``_options``
   ``pathlib`` path to the configuration file used by the package.


Major Changes
-------------

-  Added ``"--no-tty"`` option to ``command()`` method which conveniently
   tells gpg2 not to use the terminal to output messages. This has lead to
   a substantial, possibly complete, reduction in the amount of noise gpg2
   prints to the screen. Some of that printed information is helpful to
   see, though. We would add it back in places where it could be informative,
   but passing ``"--no-tty"`` has the added benefit of allowing Docker not
   to break right out of the gate of a build test. More thought on this
   is required.
-  Removed ``pathlib`` from imports. That module has been in the standard
   library since c-python3.4. This package isn't looking to be supported
   for anything older than 3.6.




Changes for version 0.5.4
=========================

Minor Changes
-------------

-  Style edits to ``PREADME.rst``.


Major Changes
-------------

-  Fixed a major bug in ``decrypt()`` which miscategorized a fingerprint scraped
   from a message as the sender's, when in fact it should be the recipient's.
   Getting the sender's fingerprint requires successfully decrypting the
   message & scraping the signature from inside if it exists. We do this
   now, raising ``LookupError`` if the signature inside has no corresponding
   public key in the package keyring.
-  Added new ``auto_encrypt()`` method which follows after ``auto_decrypt()``
   in allowing a user to attempt to encrypt a message to a recipient's
   key using the value in the ``uid`` kwarg. If there's no matching key
   in the package keyring, then the keyserver is queried for a key
   that matches ``uid`` where then ``message`` is encrypted if found, or
   ``FileNotFoundError`` is raised if not.
-  Added better exception raising throughout the ``GnuPG`` class:

   -  Now, instead of calling ``read_output()`` when the supplied ``uid``
      has no key in the package keyring, a ``LookupError`` is raised.
   -  The best attempt at deriving a 40-byte key fingerprint from ``uid`` is
      returned back through the ``LookupError`` exception object's ``value``
      attribute for downstream error handling.
   -  ``verify()`` raises ``PermissionError`` if verification cannot be
      done on the ``message`` kwarg. Raises ``LookupError`` instead if
      a public key is needed in order to attempt verification. ``verify``
      can't be used on an encrypted messages in general, unless ``message``
      is specifcally a signature, not encrypted plaintext. This is just
      not how verify works. Signatures are on the inside on encrypted
      messages. So ``decrypt()`` should be used for those instead, it
      throws if a signature is invalid on a message.
   -  A rough guide now exists for what exceptions mean, since we've given
      names & messages to the most likely errors, & helper functions
      to resolve them. Users can now expect to run into more than just
      the in decript ``CalledProcessError``. Exceptions currently being
      used include: ``LookupError``, ``PermissionError``, ``TypeError``,
      ``ValueError``, ``KeyError``, & ``FileNotFoundError``.

-  ``ValueError`` raised in ``text_export()`` & ``sign()`` switched to
   ``TypeError`` as it's only raised when their ``secret`` or ``key``
   kwargs, respectively, are not of type ``bool``.



Changes for version 0.5.3
=========================

Minor Changes
-------------

-  Fixing PyPi ``README.rst`` rendering.




Changes for version 0.5.2
=========================

Minor Changes
-------------

-  Futher test cleanups. We're now at 100% line coverage & 99% branch
   coverage.
-  Code cleanups. ``raw_packets()`` now passes the uid information it's
   gathered through the ``KeyError`` exception, in the ``value`` attribute
   instead of copying ``subprocess``'s ``output`` attribute naming convention.
-  License, coverage, package version badges added to ``README.rst``.




Changes for version 0.5.1
=========================

Minor Changes
-------------

-  Fixed inaccuracies & mess-ups in the tests. Added tests for parsing
   some legacy keys' packets with ``raw_packets()``.


Major Changes
-------------

-  Bug in the packet parser has been patched which did not correctly
   handle or recognize some legacy key packet types. This patch widens
   the pool of compatible OpenPGP versions.




Changes for version 0.5.0
=========================

Minor Changes
-------------

-  Removed coverage.py html results. They are too big, & reveal device
   specific information.




Changes for version 0.4.9
=========================

Minor Changes
-------------

-  Various code cleanups.
-  Added to test cases for auto fetch methods & packet parsing.
-  Documentation improvements: ``README.rst`` edits. ``CHANGES.rst``
   Known Issues moved to its own section at the top. Docstrings now
   indicate code args & kwargs in restructured text, double tick
   format.
-  Added ``use-agent`` back into the gpg2.conf file to help gnupg to not
   open the system pinentry window. This may have implications for
   anonymity since multiple instances runnning on a user machine will
   be able to use the same agent to decrypt message's, even if the
   decrypting instance wasn't the **intended** recipient. This may be
   removed again. A factor in this decision is that, it's not clear
   whether removing it or adding ``no-use-agent`` would even `have an impact`_
   on the gpg-agent's decisions.
-  ``_session``, ``_connector``, ``session`` & ``connector`` contructors
   were renamed to title case, since they are class references or are
   class factories. They are now named ``_Session``, ``_Connector``,
   ``Session`` & ``Connector``.
-  Added some functionality to ``setup.py`` so that the ``long_description``
   on PyPI which displays both ``README.rst`` & ``CHANGES.rst``, will
   also be displayed on github through a combined ``README.rst`` file.
   The old ``README.rst`` is now renamed ``PREADME.rst``.

.. _have an impact: https://stackoverflow.com/questions/47273922/purpose-of-gpg-agent-in-gpg2


Major Changes
-------------

-  100% test coverage!
-  Fixed bug in ``raw_packets()`` which did not return the packet
   information when gnupg throws a "no private key" error. Now the
   packet information is passed in the ``output`` attribute of the
   ``KeyError`` exception up to ``packet_fingerprint()`` and
   ``list_packets()``. If another cause is determined for the error, then
   ``CalledProcessError`` is raised instead.
-  ``packet_fingerprint()`` now returns a 16 byte key ID when parsing
   packets of encrypted messages which would throw a gnupg "no private
   key" error. The longer 40 byte fingerprint is not available in the
   plaintext packets.
-  New ``list_packets()`` method added to handle the error scraping of
   ``raw_packets()`` & return the ``target``'s metadata information in
   a more readable format.
-  Fixed bug in ``format_list_keys()`` which did not properly parse
   ``raw_list_keys(secret=False)`` when ``secret`` was toggled to ``True``
   to display secret keys. The bug would cause the program to falsely
   show that only one secret key exists in the package keyring,
   irrespective of how many secret keys were actually there.
-  Added a second round of fingerprint finding in ``decrypt()`` and
   ``verify()`` to try at returning more accurate results to callers and
   in the raised exception's ``value`` attribute used by ``auto_decrypt()``
   & ``auto_verify()``.



Changes for version 0.4.8
=========================

Minor Changes
-------------

-  Fixed typos across the code.
-  Added to test cases.
-  Documentation improvements. ``CHANGES.md`` has been converted to
   ``CHANGES.rst`` for easy integration into ``README.rst`` and
   ``long_description`` of ``setup.py``.
-  ``README.rst`` tutorial expanded.
-  Condensed command constructions in ``set_base_command()`` and
   ``gen_key()`` by reducing redundancy.
-  Fixed ``delete()`` method's print noisy output when called on a key
   which doesn't have a secret key in the package's keyring.


Major Changes
-------------

-  Added a ``secret`` kwarg to ``list_keys()`` method which is a boolean
   toogle between viewing keys with public keys & viewing keys with
   secret keys.
-  Added a reference to the asyncio.get_event_loop().run_until_complete
   function in the package. It is now importable with
   ``from tiny_gnupg import run`` or ``from tiny_gnupg import *``. It
   was present in all of the tutorials, & since we haven’t decided to
   go either all async or sync yet, it’s a nice helper.
-  Added ``raw_packets(target="")`` method which takes in OpenPGP data,
   like a message or key, & outputs the raw terminal output of the
   ``--list-packets`` option. Displays very detailed information of all
   the OpenPGP metadata on ``target``.
-  Added ``packet_fingerprint(target="")`` method which returns the
   issuer fingerprint scraped off of the metadata returned from
   ``raw_packets(target)``. This is a very effective way to retrieve
   uid information from OpenPGP signatures, messages & keys to
   determine beforehand whether the associated sender's key is or isn't
   already in the package's keyring.




Changes for version 0.4.7
=========================

Minor Changes
-------------

-  Fixed typos across the code.
-  Added to test cases.
-  Added tests explanation in ``test_tiny_gnupg.py``.
-  Documentation improvements.


Major Changes
-------------

-  Added exception hooks to ``decrypt()`` & ``verify()`` methods. They
   now raise ``KeyError`` when the OpenPGP data they’re verifying
   require a signing key that’s not in the package’s keyring. The
   fingerprint of the required key is printed out & stored in the
   ``value`` attribute of the raised exception.
-  Added new ``auto_decrypt()`` & ``auto_verify()`` async methods
   which catch the new exception hooks to automatically try a torified
   keyserver lookup before raising a KeyError exception. If a key is
   found, it’s downloaded & an attempt is made to verify the data.




Changes for version 0.4.6
=========================

Minor Changes
-------------

-  Added to test cases.
-  Changed the project long description in the ``README.rst``.
-  Added docstrings to all the methods in the ``GnuPG`` class, & the
   class itself.


Major Changes
-------------

-  Turned off options in gpg2.conf ``require-cross-certification`` and
   ``no-comment`` because one or both may be causing a bug where using
   private keys raises an “unusable private key” error.




Changes for version 0.4.5
=========================

Minor Changes
-------------

-  Updated package metadata files to be gpg2.conf aware.


Major Changes
-------------

-  Added support for a default package-wide gpg2.conf file.




Changes for version 0.4.4
=========================

Minor Changes
-------------

-  Added new tests. We’re at 95% code coverage.


Major Changes
-------------

-  Changed the default expiration date on generated keys from never to 3
   years after created. This is both for the integrity of the keys, but
   also as a courtesy to the key community by not recklessly creating
   keys that never expire.

-  Added ``revoke(uid)`` method, which revokes the key with matching
   ``uid`` if the secret key is owned by the user & the key passphrase
   is stored in the instance’s ``passphrase`` attribute.




Changes for version 0.4.3
=========================

Minor Changes
-------------

-  Changed package description to name more specifically the kind of ECC
   keys this package handles.
-  Removed the trailing newline character that was inserted into the end
   of every ``encrypt()`` & ``sign()`` message.
-  Added new tests.


Major Changes
-------------

-  Fixed bug in ``__init__()`` caused by the set_base_command() not
   being called before the base commands are used. This leading to the
   fingerprint for a persistent user not being set automatically.




Changes for version 0.4.2
=========================

Minor Changes
-------------

-  Added some keyword argument names to ``README.rst`` tutorials.
-  Added section in ``README.rst`` about torification.


Major Changes
-------------

-  Added a check in ``encrypt()`` for the recipient key in the local
   keyring which throws if it doesn’t exist. This is to prevent gnupg
   from using wkd to contact the network to find the key on a keyserver.
-  Added a new ``torify=False`` kwarg to ``__init__()`` which prepends
   ``"torify"`` to each gpg2 command if set to ``True``. This will make
   sure that if gnupg makes any silent connections to keyservers or the
   web, that they are run through tor & don’t expose a users ip
   address inadvertently.




Changes for version 0.4.1
=========================

Minor Changes
-------------

-  Fixed typos in ``tiny_gnupg.py``.




Changes for version 0.4.0
=========================

Minor Changes
-------------

-  Added keywords to ``setup.py``
-  Added copyright notice to LICENSE file.
-  Code cleanups.
-  Updated ``README.rst`` tutorials.
-  Added new tests.
-  Include .gitignore in MANIFEST.in for PyPI.
-  Made all path manipulations more consistent by strictly using
   pathlib.Path for directory specifications.
-  Added strict truthiness avoidance to ``sign()`` for the ``key``
   boolean kwarg.
-  Added strict truthiness avoidance to ``text_export()`` for the
   ``secret`` boolean kwarg.


Major Changes
-------------

-  Added ``key`` kwarg to the ``sign(target="", key=False)`` method to
   allow users to toggle between signing arbitrary data & signing a
   key in the package’s local keyring.
-  Changed the ``message`` kwarg in ``sign(message="")`` to ``target``
   so it is also accurate when the method is used to sign keys instead
   of arbitrary data.




Changes for version 0.3.9
=========================

Minor Changes
-------------

-  Added new tests.


Major Changes
-------------

-  Fixed new crash caused by ``--batch`` keyword in ``encrypt()``. When
   a key being used to encrypt isn’t ultimately trusted, gnupg raises an
   error, but this isn’t a desired behavior. So, ``--batch`` is removed
   from the command sent from the method.




Changes for version 0.3.8
=========================

Minor Changes
-------------

-  Added new tests.
-  Removed ``base_command()`` method because it was only a layer of
   indirection. It was merged into ``command()``.


Major Changes
-------------

-  Added the ``--batch``, ``--quiet`` & ``--yes`` arguments to the
   default commands contructed by the ``command()`` method.
-  Added the ``--quiet`` & ``--yes`` arguments to the command
   constructed internally to the ``gen_key()`` method.
-  Added a general uid —> fingerprint uid conversion in ``delete()`` to
   comply with gnupg limitations on how to call functions that
   automatically assume yes to questions. The Up-shot is that
   ``delete()`` is now fully automatic, requiring no user interaction.




Changes for version 0.3.7
=========================

Minor Changes
-------------

-  Added new tests.
-  Typos & inaccuracies fixed around the code & documentation.


Major Changes
-------------

-  Added new ``secret`` kwargs to ``text_export(uid, secret=bool)`` and
   ``file_export(path, uid, secret=bool)`` to allow secret keys to be
   exported from the package’s environment.
-  Added new ``post(url, **kw)`` & ``get(url, **kw)`` methods to allow
   access to the networking tools without having to manually construct
   the ``network_post()`` & ``network_get()`` context managers. This
   turns network calls into one liners that can be more easily wrapped
   with an asyncio ``run`` function.




Changes for version 0.3.6
=========================

Minor Changes
-------------

-  Added new tests for networking methods.
-  Documentation updates & accuracy fixes.


Major Changes
-------------

-  Removed a check in ``network_import()`` which wasn’t useful and
   should’ve been causing problems with imports, even though the tests
   didn’t seem to notice.




Changes for version 0.3.5
=========================

Minor Changes
-------------

-  Switched the aiocontext package license with the license for
   asyncio-contextmanager.


Major Changes
-------------

-  The packaging issues seem to be resolved. Packaging as v0.3.5-beta,
   the first release that did not ship completely broken through pip
   install –user tiny_gnupg.




Changes for version 0.3.4
=========================

Major Changes
-------------

-  Fixing a major bug in the parameters passed to ``setup()`` which did
   not correctly tell setuptools to package the gpghome folder & gpg2
   binary. This may take a few releases to troubleshoot & bug fix
   fully.




Changes for version 0.3.3
=========================

Major Changes
-------------

-  Fixed a big bug where the wrong package was imported with the same
   name as the intended module. AioContext was imported in setuptools,
   but the package that is needed is asyncio-contextmanager for its
   aiocontext module. This lead to the program being un-runable due to
   an import error.




Changes for version 0.3.2
=========================

Minor Changes
-------------

-  Rolled back the changes in ``trust()`` that checked for trust levels
   on keys to avoid sending an unnecessary byte of data through the
   terminal. Mostly because the attempted fix did not fix the issue. And
   the correct fix involves a wide branching of state & argument
   checking. That runs contrary to the goal of the package for
   simplicity, so it isn’t going to be addressed for now.
-  Edited some of the ``README.rst`` tutorials.


Major Changes
-------------

-  Fix bug in ``file_import()`` method where await wasn’t called on the
   keyfile.read() object, leading to a crash.




Changes for version 0.3.1
=========================

Minor Changes
-------------

-  Fixed a bug in ``trust()`` which caused an extra ``b“y\n”``
   to be sent to the interactive prompt when setting keys as anything
   but ultimately trusted. This was because there’s an extra terminal
   dialog asking for a “y” confirmation that is not there when a key is
   being set as ultimately trusted. This didn’t have a serious effect
   other than displaying a “Invalid command (try ‘help’)” dialog.
-  Removed ``local_user`` kwarg from the ``raw_list_keys()`` and
   ``trust()`` methods, as it doesn’t seem to matter which “user”
   perspective views the list of keys or modifies trust. It is very
   likely always displaying keys from the perspective of the global
   agent.
-  Typos, redundancies & naming inaccuracies fixed around the code and
   documentation.
-  Tests updated & added to.


Major Changes
-------------

-  Fixed a bug in ``encrypt()`` which caused a ``“y\n”`` to be
   prepended to plaintext that was sent to ultimately trusted keys. This
   was because there’s an extra terminal dialog asking for a “y”
   confirmation that is not there when a key is ultimately trusted.
-  Added a ``key_trust(uid)`` method to allow easy determination of
   trust levels set on keys in the local keyring.




Changes for version 0.3.0
=========================

Minor Changes
-------------

-  Changed MANIFEST.in to a more specific include structure, & a
   redundant exclude structure, to more confidently keep development
   environment key material from being uploaded during packaging.


Major Changes
-------------

-  Overhauled the ``gen_key()`` which now creates a different set of
   default keys. We are no longer creating one primary key which does
   certifying & signing, with one subkey which handles encryption.
   Instead, we create one certifying primary key, with three subkeys,
   one each for handling encryption, authentication, & signing. This
   is a more theoretically secure default key setup, & represents a
   common best-practice.




Changes for version 0.2.9
=========================

Minor Changes
-------------

-  Edited some of the ``README.rst`` tutorials
-  Changed ``file_import()``\ ’s ``filename`` kwarg to ``path`` for
   clarity.
-  Fixed bug in ``trust()`` which would allow a float to be passed to
   the terminal when an integer was needed.
-  Changed the way the email address in displayed in
   ``network_export()``, removing the surrounding list brackets.
-  Changed the FILE_PATH global to HOME_PATH for clarity.
-  Changed the ``id_link`` variable in ``network_import()`` to
   ``key_url`` for clarity.


Major Changes
-------------

-  Fixed a bug in ``format_list_keys()`` which would imporperly split
   the output string when uid information contained the ``"pub"``
   string.




Changes for version 0.2.8
=========================

Minor Changes
-------------

-  Edited some of the ``README.rst`` tutorials.


Major Changes
-------------

-  Fixed a bug in the ``trust()`` method which caused it to never
   complete execution.
-  Fixed a bug in the ``trust()`` method which falsely made 4 the
   highest trust level, instead of 5.




Changes for version 0.2.7
=========================

Minor Changes
-------------

-  Fixed statement in ``README.rst`` describing bug #T4393.




Changes for version 0.2.6
=========================

Minor Changes
-------------

-  Typos, redundancies & naming inaccuracies fixed around the code and
   documentation.
-  Added a new POST request tutorial to the ``README.rst``.
-  Added ``"local_user"`` kwarg to some more methods where the output
   could at least be partially determined by the point of view of the
   key gnupg thinks is the user’s.


Major Changes
-------------

-  Added a signing toggle to the ``encrypt(sign=True)`` method. Now, the
   method still automatically signs encrypted messages, but users can
   choose to turn off this behavior.
-  Added a ``trust(uid="", level=4)`` method, which will allow users to
   sign keys in their keyring on a trust scale from 1 to 4.
-  Fixed a bug in ``set_fingerprint(uid="")`` which mistakenly used an
   ``email`` parameter instead of the locally available ``uid`` kwarg.




Changes for version 0.2.5
=========================

Minor Changes
-------------

-  Typos, redundancies & naming inaccuracies fixed around the code and
   documentation.
-  Tests updated & added to.
-  Changed ``raw_network_export()`` & ``raw_network_verify()`` methods
   into ``raw_api_export()`` & ``raw_api_verify()``, respectively.
   This was done for more clarity as to what those methods are doing.


Major Changes
-------------

-  Added ``sign(message)`` & ``verify(message)`` methods.
-  Changed the ``keyserver`` & ``searchserver`` attributes into
   properties so that custom ``port`` attribute changes are now
   reflected in the constructed url, & the search string used by a
   custom keyserver can also be reflected.
-  Moved all command validation to the ``read_output()`` method which
   simplifies the construction of ``command()`` & will automatically
   ``shlex.quote()`` all commands, even those hard-coded into the
   program.
-  Fixed bug in ``set_homedir()`` which did not construct the default
   gpghome directory string correctly depending on where the current
   working directory of the calling script was.
-  Added ``local_user`` kwarg to ``encrypt()`` & ``sign()`` so a user
   can specify which key to use for signing messages, as gnupg
   automatically signs with whatever key it views as the default user
   key. Instead, we assume mesasges are to be signed with the key
   associated with the email address of a GnuPG class instance, or the
   key defined by the ``local_user`` uid if it is passed.
-  Fixed –list-keys terminal output parsing. We now successfully parse
   & parameterize the output into email addresses & fingerprints, of
   a larger set of types of keys.
-  Added ``delete()`` method for removing both public & private keys
   from the local keyring. This method still requires some user
   interaction because a system pinentry-type dialog box opens up to
   confirm deletion. Finding a way to automate this to avoid user
   interaction is in the work.
-  Added automating behavior to the ``sign()`` & ``encrypt()`` methods
   so that keys which haven’t been verified will still be used. This is
   done by passing “y” (yes) to the terminal during the process of the
   command.




Changes for version 0.2.4
=========================

Minor Changes
-------------

-  Updated ``setup.py`` with more package information.
-  Typos, redundancies & naming inaccuracies fixed around the code and
   documentation.
-  Tests updated & added to.




Changes for version 0.2.3
=========================

Minor Changes
-------------

-  Typos & naming inaccuracies fixed around the code and
   documentation.
-  Added package to `git repo`_
-  Added git repo url to ``setup.py``.
-  The ``port`` attribute is currently unused. It may be removed if it
   remains purposeless.




Changes for version 0.2.2
=========================

Minor Changes
-------------

-  Typos & naming inaccuracies fixed around the code and
   documentation.
-  Switched the internal networking calls to use the higher level
   ``network_get()`` & ``network_post()`` methods.
-  Removed redundant ``shlex.quote()`` calls on args passed to the
   ``command()`` method.
-  Tests updated & added to.

.. _git repo: https://github.com/rmlibre/tiny_gnupg.git




Changes for version 0.2.1
=========================

Minor Changes
-------------

-  The names of some existing methods were changed. ``parse_output()``
   is now ``read_output()``. ``gpg_directory()`` is now
   ``format_homedir()``. The names of some existing attributes were
   changed. ``gpg_path`` is now ``executable``, with its parent folder
   uri now stored in ``home``. ``key_id`` is now ``fingerprint`` to
   avoid similarities with the naming convention used for the methods
   which query the package environment keys for uid information,
   i.e. ``key_fingerprint()`` & ``key_email()``.


Major Changes
-------------

-  Good riddance to the pynput library hack! We figured out how to
   gracefully send passphrases & other inputs into the gpg2
   commandline interface. This has brought major changes to the package,
   & lots of increased functionality.
-  Many added utilities:

   -  Keys generated with the ``gen_key()`` method now get stored in a
      local keyring instead of the operating system keyring.
   -  aiohttp, aiohttp_socks used to power the keyserver queries and
      uploading features. All contact with the keyserver is done over
      tor, with async/await syntax. ``search(uid)`` to query for a key
      with matches to the supplied uid, which could be a fingerprint or
      email address. ``network_import(uid)`` to import a key with
      matches to the supplied uid. ``network_export(uid)`` to upload a
      key in the package’s keyring with matches to the supplied uid to
      the keyserver. Also, raw access to the aiohttp.ClientSession
      networking interface is available by using
      ``async with instance.session as session:``. More info is
      available in the `aiohttp docs`_
   -  New ``text_import(key)``, ``file_import(filename)``,
      ``text_export(key)``, & ``file_export(path, uid)`` methods for
      importing & exporting keys from key strings or files.
   -  New ``reset_daemon()`` method for refreshing the system gpg-agent
      daemon if errors begin to occur from manual deletion or
      modification of files in the package/gpghome/ directory.
   -  New ``encrypt(message, recipient_uid)`` & ``decrypt(message)``
      methods. The ``encrypt()`` method automatically signs the message,
      therefore needs the key passphrase to be stored in the
      ``passphrase`` attribute. The same goes for the ``decrypt()``
      method.
   -  The ``command(*options)``, ``encode_inputs(*inputs)``, and
      ``read_output(commands, inputs)`` methods can be used to create
      custom commands to the package’s gpg2 environment. This allows for
      flexibility without hardcoding flexibility into every method,
      which would increase code size & complexity. The ``command()``
      method takes a series of options that would normally be passed to
      the terminal gpg2 program (such as –encrypt) & returns a list
      with those options included, as well as, the other boiler-plate
      options (like the correct path to the package executable, & the
      package’s local gpg2 environment.). ``encode_inputs()`` takes a
      series of inputs that will be needed by the program called with
      the ``command()`` instructions, & ``bytes()`` encodes them with
      the necessary linebreaks to signal separate inputs.
      ``read_output()`` takes the instructions from ``command()`` and
      inputs from ``encode_inputs()`` & calls
      ``subprocess.check_output(commands, input=inputs).decode()`` on
      them to retrieve the resulting terminal output.

.. _aiohttp docs: https://docs.aiohttp.org/en/stable/client_advanced.html#client-session
