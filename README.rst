tiny_gnupg - A small-as-possible solution for handling GnuPG ECC keys.
======================================================================
A small, simple & intuitive wrapper for creating, using and managing
GnuPG's Ed-25519 curve keys. We are in favor of reducing code size and
complexity with strong and bias defaults over flexibility in the api.
Contributions welcome.

This package is only seeking to be compatible with linux systems, and
is currently in unstable beta. It works like a charm, but there's likely
bugs floating around, and the api is subject to change.


Usage Example
-------------

.. code:: python

    from tiny_gnupg import GnuPG

    username = "username"
    email = "username@user.net"
    passphrase = "test_user_passphrase"
    gpg = GnuPG(username, email, passphrase)

    # This will generate a primary ed25519 ECC certifying key, and three
    # subkeys, one each for the authentication, encryption, and signing
    # functionalities.
    gpg.gen_key()

    # Now this fingerprint can be used with arbitrary gpg2 commands.
    gpg.fingerprint

    # But the key is stored in the package's local keyring. To
    # talk to the package's gpg environment, an arbitrary command
    # can be constructed like this ->
    options = ["--armor", "--encrypt", "-r", gpg.fingerprint]
    command = gpg.command(*options)
    inputs = gpg.encode_inputs("Message to myself")
    output = gpg.read_output(command, inputs)

    # If a command would invoke the need for a passphrase, the with_passphrase
    # kwarg (gpg.command(*options, with_passphase=True)) can be set to True.
    # The passphrase then needs to be the first arg passed to encode_inputs
    # (gpg.encode_inputs(passphrase, *other_inputs))


    # The list of keys in the package's environment can be accessed
    # from the list_keys() method, which returns a dict ->
    gpg.list_keys()
    # >>> {fingerprint: email_address, ...}

    # Or retrieve a specific key where a searchable portion of its uid
    # information is known, like an email address or fingerprint ->
    gpg.list_keys("username@user.net")

    # Let's encrypt a message to Alice, whose public key is stored
    # on keys.openpgp.org/.
    # First, we'll import Alice's key from the keyserver (This requires
    # a tor system installation. Or an open tor browser, and the tor_port
    # attribute set to 9150) ->
    import asyncio

    run = asyncio.get_event_loop().run_until_complete

    run(gpg.network_import("alice@email.domain"))

    # Then encrypt a message with Alice's key and sign it ->
    msg = "So, what's the plan this Sunday, Alice?"
    encrypted_message = gpg.encrypt(msg, "alice@email.domain", sign=True)

    # We could directly send a copy of our key to Alice, or upload it to
    # the keyserver. Alice will need a copy so the signature on the
    # message can be verified ->
    run(gpg.network_export(gpg.fingerprint))

    # Alice could now import our key (after we do an email verification
    # with the keyserver) ->
    run(gpg.network_import("username@user.net"))

    # Then Alice can simply receive the encrypted message and decrypt it ->
    decrypted_msg = gpg.decrypt(encrypted_message)

On most systems, because of a bug in GnuPG_, email verification of uploaded keys will be necessary for others to import them from the keyserver. That's because GnuPG will throw an error immediately upon trying to import keys with their uid information stripped off. We will replace the gpg2 executable as soon as a patch becomes available upstream.

If the gpg2 executable doesn't work on your system, replace it with a copy of the executable found on your system. The package's executable can be found at: package_path/gpghome/gpg2. This path is also available from a class instance under the instance.executable attribute. Your system gpg2 executable is probably located at: /usr/bin/gpg2. You could also type: whereis gpg2 :to find it. If it's not there, then you'll have to install it with your system's equivalent of: sudo apt-get install gnupg2.

.. _GnuPG: https://dev.gnupg.org/T4393



Networking Example
------------------

.. code:: python

    #
    # Since we use SOCKSv5 over tor for all of our networking, as well
    # as the user-friendly aiohttp + aiohttp_socks libraries, the tor
    # networking interface is also available to users. These utilities
    # allow arbitrary POST and GET requests to clearnet, or onionland,
    # websites ->
    import asyncio
    from tiny_gnupg import GnuPG


    async def read_url(url):
        client = GnuPG()
        async with client.network_get(url) as response:
            return await response.text()


    run = asyncio.get_event_loop().run_until_complete

    # Now we can read webpages with GET requests ->
    page_html = run(read_url("https://keys.openpgp.org/"))

    # Let's try onionland ->
    url = "http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion/"
    onion_page_html = run(read_url(url))

    # Check your ip address for fun ->
    ip_addr = run(read_url("https://icanhazip.com/"))


    # POST requests can also be sent with the network_post() method.
    # Let's use a POST request to send the keyserver a new key we
    # create ->
    async def post(gpg, url, payload=""):
        async with gpg.network_post(url, json=payload) as response:
            return await response.text()


    gpg = GnuPG("username", "username@user.net", "test_user_passphrase")
    gpg.gen_key()
    url = gpg.keyserver_export_api
    payload = {"keytext": gpg.text_export(gpg.fingerprint)}
    api_token_json = run(post(gpg, url, payload))
    # And there we have it, it's super simple. And these requests have
    # the added benefit of being completely routed through tor. The
    # keyserver here also has a v3 onion address which we use to query,
    # upload, and import keys. This provides a nice, default layer of
    # privacy to our communication needs. Have fun little niblets!


    # These networking tools work off instances of aiohttp.ClientSession.
    # To learn more about how to use their POST and GET requests, you
    # can read the docs here:
    # https://docs.aiohttp.org/en/stable/client_advanced.html#client-session


Extras
------

.. code:: python

    # It turns out that the encrypt() method automatically signs the
    # message being encrypted. So, the `sign=False` flag only has to be
    # passed when a user doesn't want to sign a message ->
    encrypted_unsigned_message = gpg.encrypt(
        message="<-- Unknown sender",
        uid="alice@email.domain",  # sending to alice
        sign=False,
    )

    # It also turns out, a user can sign things independently from
    # encrypting ->
    signed_data = gpg.sign("maybe a hash of a file?")

    # And verify data as well ->
    gpg.verify(signed_data)  # throws if invalid

    # Importing key files is also a thing ->
    import asyncio

    run = asyncio.get_event_loop().run_until_complete

    path_to_file = "/home/user/keyfiles/"
    run(gpg.file_import(path=path_to_file + "alices_key.asc"))

    # And exporting ->
    run(gpg.file_export(path=path_to_file, uid=gpg.email))


    # When a user is done with a key, it can be deleted from the package
    # keyring like this ->
    gpg.delete("username@user.net")  # You'll have to manually click
                                     # the confirm button, though.



