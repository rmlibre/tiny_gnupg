# Changes for version 0.3.6
## Known Issues
- Because of Debian [bug #930665](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=930665), and related GnuPG [bug #T4393](https://dev.gnupg.org/T4393), importing keys from the default keyserver [keys.openpgp.org](https://keys.openpgp.org/) doesn't work automatically on all systems. Not without email confirmation, at least. That's because the keyserver will not publish uid information attached to a key before a user confirms access to the email address assigned to the uploaded key. And, because GnuPG folks are still holding up the merging, and back-porting, of patches that would allow GnuPG to automatically handle keys without uids gracefully. This effects the `network_import()` method specifically, but also the `text_import()` and `file_import()` methods, if they happen to be passed a key or filename argument which refers to a key without uid information. The gpg2 binary in this package can be replaced manually if a user's system has access to a patched version.
- This program may only be reliably compatible with keys that are also created with this program. That's because our terminal parsing is reliant on specific metadata to be similar across all encountered keys. It seems most keys have successfully been parsed with recent updates, though more testing is needed.
- Currently, the package is part synchronous, and part asynchronous. This is not ideal, so a decision has to be made: either to stay mixed style, or choose one consistent style.
- We're still in unstable and have to build out our test suite. Contributions welcome.
- The `delete()` method isn't completely automated. There are system dialogs that pop up asking for user confirmation of the delete process. This isn't ideal, but it's not clear at the moment how to automate those answers.
## Minor Changes
- Added new tests for networking methods.
- Documentation updates and accuracy fixes.
## Major Changes
- Removed a check in `network_import()` which wasn't useful and was should've been causing problems with imports, even though the tests didn't seem to notice.


# Changes for version 0.3.5
## Minor Changes
- Switched the aiocontext package license with the license for asyncio-contextmanager.
## Major Changes
- The packaging issues seem to be resolved. Packaging as v0.3.5-beta, the first release that did not ship completely broken through pip install --user tiny_gnupg.


# Changes for version 0.3.4
## Major Changes
- Fixing a major bug in the parameters passed to `setup()` which did not correctly tell setuptools to package the gpghome folder and gpg2 binary. This may take a few releases to troubleshoot and bug fix fully.


# Changes for version 0.3.3
## Major Changes
- Fixed a big bug where the wrong package was imported with the same name as the intended module. AioContext was imported in setuptools, but the package that is needed is asyncio-contextmanager for its aiocontext module. This lead to the program being un-runable due to an import error.


# Changes for version 0.3.2
## Minor Changes
- Rolled back the changes in `trust()` that checked for trust levels on keys to avoid sending an unnecessary byte of data through the terminal. Mostly because the attempted fix did not fix the issue. And the correct fix involves a wide branching of state and argument checking. That runs contrary to the goal of the package for simplicity, so it isn't going to be addressed for now.
- Edited some of the README.rst tutorials.
## Major Changes
- Fix bug in `file_import()` method where await wasn't called on the keyfile.read() object, leading to a crash.


# Changes for version 0.3.1
## Minor Changes
- Fixed a bug in `trust()` which caused an extra "y\n" to be sent to the interactive prompt when setting keys as anything but ultimately trusted. This was because there's an extra terminal dialog asking for a "y" confirmation that is not there when a key is being set as ultimately trusted. This didn't have a serious effect other than displaying a "Invalid command  (try 'help')" dialog.
- Removed `local_user` kwarg from the `raw_list_keys()` and `trust()` methods, as it doesn't seem to matter which "user" perspective views the list of keys or modifies trust. It is very likely always displaying keys from the perspective of the global agent.
- Typos, redundancies and naming inaccuracies fixed around the code and documentation.
- Tests updated and added to.
## Major Changes
- Fixed a bug in `encrypt()` which caused a "y\n" to be prepended to plaintext that was sent to ultimately trusted keys. This was because there's an extra terminal dialog asking for a "y" confirmation that is not there when a key is ultimately trusted.
- Added a `key_trust(uid)` method to allow easy determination of trust levels set on keys in the local keyring.


# Changes for version 0.3.0
## Minor Changes
- Changed MANIFEST.in to a more specific include structure, and a redundant exclude structure, to more confidently keep development environment key material from being uploaded during packaging.
## Major Changes
- Overhauled the `gen_key()` which now creates a different set of default keys. We are no longer creating one primary key which does certifying and signing, with one subkey which handles encryption. Instead, we create one certifying primary key, with three subkeys, one each for handling encryption, authentication, and signing. This is a more theoretically secure default key setup, and represents a common best-practice.


# Changes for version 0.2.9
## Minor Changes
- Edited some of the README.rst tutorials
- Changed `file_import()`'s `filename` kwarg to `path` for clarity.
- Fixed bug in `trust()` which would allow a float to be passed to the terminal when an integer was needed.
- Changed the way the email address in displayed in `network_export()`, removing the surrounding list brackets.
- Changed the FILE_PATH global to HOME_PATH for clarity.
- Changed the `id_link` variable in `network_import()` to `key_url` for clarity.
## Major Changes
- Fixed a bug in `format_list_keys()` which would imporperly split the output string when uid information contained the `"pub"` string.


# Changes for version 0.2.8
## Minor Changes
- Edited some of the README.rst tutorials.
## Major Changes
- Fixed a bug in the `trust()` method which caused it to never complete execution.
- Fixed a bug in the `trust()` method which falsely made 4 the highest trust level, instead of 5.


# Changes for version 0.2.7
## Minor Changes
- Fixed statement in README.rst describing bug #T4393.


# Changes for version 0.2.6
## Minor Changes
- Typos, redundancies and naming inaccuracies fixed around the code and documentation.
- Added a new POST request tutorial to the README.rst.
- Added `"local_user"` kwarg to some more methods where the output could at least be partially determined by the point of view of the key gnupg thinks is the user's.
## Major Changes
- Added a signing toggle to the `encrypt(sign=True)` method. Now, the method still automatically signs encrypted messages, but users can choose to turn off this behavior.
- Added a `trust(uid="", level=4)` method, which will allow users to sign keys in their keyring on a trust scale from 1 to 4.
- Fixed a bug in `set_fingerprint(uid="")` which mistakenly used an `email` parameter instead of the locally available `uid` kwarg.


# Changes for version 0.2.5
## Minor Changes
- Typos, redundancies and naming inaccuracies fixed around the code and documentation.
- Tests updated and added to.
- Changed `raw_network_export()` and `raw_network_verify()` methods into `raw_api_export()` and `raw_api_verify()`, respectively. This was done for more clarity as to what those methods are doing.
## Major Changes
- Added `sign(message)` and `verify(message)` methods.
- Changed the `keyserver` and `searchserver` attributes into properties so that custom `port` attribute changes are now reflected in the constructed url, and the search string used by a custom keyserver can also be reflected.
- Moved all command validation to the `read_output()` method which simplifies the construction of `command()` and will automatically `shlex.quote()` all commands, even those hard-coded into the program.
- Fixed bug in `set_homedir()` which did not construct the default gpghome directory string correctly depending on where the current working directory of the calling script was.
- Added `local_user` kwarg to `encrypt()` and `sign()` so a user can specify which key to use for signing messages, as gnupg automatically signs with whatever key it views as the default user key. Instead, we assume mesasges are to be signed with the key associated with the email address of a GnuPG class instance, or the key defined by the `local_user` uid if it is passed.
- Fixed --list-keys terminal output parsing. We now successfully parse and parameterize the output into email addresses and fingerprints, of a larger set of types of keys.
- Added `delete()` method for removing both public and private keys from the local keyring. This method still requires some user interaction because a system pinentry-type dialog box opens up to confirm deletion. Finding a way to automate this to avoid user interaction is in the work.
- Added automating behavior to the `sign()` and `encrypt()` methods so that keys which haven't been verified will still be used. This is done by passing "y" (yes) to the terminal during the process of the command.


# Changes for version 0.2.4
## Minor Changes
- Updated `setup.py` with more package information.
- Typos, redundancies and naming inaccuracies fixed around the code and documentation.
- Tests updated and added to.


# Changes for version 0.2.3
## Minor Changes
- Typos and naming inaccuracies fixed around the code and documentation.
- Added package to [git repo](https://github.com/rmlibre/tiny_gnupg.git)
- Added git repo url to `setup.py`.
- The `port` attribute is currently unused. It may be removed if it remains purposeless.


# Changes for version 0.2.2
## Minor Changes
- Typos and naming inaccuracies fixed around the code and documentation.
- Switched the internal networking calls to use the higher level `network_get()` and `network_post()` methods.
- Removed redundant `shlex.quote()` calls on args passed to the `command()` method.
- Tests updated and added to.


# Changes for version 0.2.1
## Minor Changes
- The names of some existing methods were changed. `parse_output()` is now `read_output()`. `gpg_directory()` is now `format_homedir()`. The names of some existing attributes were changed. `gpg_path` is now `executable`, with its parent folder uri now stored in `home`. `key_id` is now `fingerprint` to avoid similarities with the naming convention used for the methods which query the package environment keys for uid information, i.e. `key_fingerprint()` and `key_email()`.
## Major Changes
- Good riddance to the pynput library hack! We figured out how to gracefully send passphrases and other inputs into the gpg2 commandline interface. This has brought major changes to the package, and lots of increased functionality.
- Many added utilities:
    - Keys generated with the `gen_key()` method now get stored in a local keyring instead of the operating system keyring.
    - aiohttp, aiohttp_socks used to power the keyserver queries and uploading features. All contact with the keyserver is done over tor, with async/await syntax. `search(uid)` to query for a key with matches to the supplied uid, which could be a fingerprint or email address. `network_import(uid)` to import a key with matches to the supplied uid. `network_export(uid)` to upload a key in the package's keyring with matches to the supplied uid to the keyserver. Also, raw access to the aiohttp.ClientSession networking interface is available by using `async with instance.session as session:`. More info is available in the [aiohttp docs](https://docs.aiohttp.org/en/stable/client_advanced.html#client-session)
    - New `text_import(key)`, `file_import(filename)`, `text_export(key)`, and `file_export(path, uid)` methods for importing and exporting keys from key strings or files.
    - New `reset_daemon()` method for refreshing the system gpg-agent daemon if errors begin to occur from manual deletion or modification of files in the package/gpghome/ directory.
    - New `encrypt(message, recipient_uid)` and `decrypt(message)` methods. The `encrypt()` method automatically signs the message, therefore needs the key passphrase to be stored in the `passphrase` attribute. The same goes for the `decrypt()` method.
    - The `command(*options)`, `encode_inputs(*inputs)`, and `read_output(commands, inputs)` methods can be used to create custom commands to the package's gpg2 environment. This allows for flexibility without hardcoding flexibility into every method, which would increase code size and complexity. The `command()` method takes a series of options that would normally be passed to the terminal gpg2 program (such as --encrypt) and returns a list with those options included, as well as, the other boiler-plate options (like the correct path to the package executable, and the package's local gpg2 environment.). `encode_inputs()` takes a series of inputs that will be needed by the program called with the `command()` instructions, and `bytes()` encodes them with the necessary linebreaks to signal separate inputs. `read_output()` takes the instructions from `command()` and inputs from `encode_inputs()` and calls `subprocess.check_output(commands, input=inputs).decode()` on them to retrieve the resulting terminal output.
