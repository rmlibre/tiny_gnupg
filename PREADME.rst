tiny_gnupg - A small-as-possible solution for handling GnuPG ed25519 ECC keys.
===============================================================================
A linux specific, small, simple & intuitive wrapper for creating, using
and managing GnuPG's Ed25519 curve keys. In our design, we favor
reducing code size & complexity with strong, bias defaults over
flexibility in the api. Our goal is to turn the powerful, complex,
legacy gnupg system into a fun and safe tool to develop with.

This project is currently in unstable beta. It works like a charm, but
there's likely, and often bugs floating around, and the api is subject
to change. Contributions are welcome.




.. image:: https://badge.fury.io/py/tiny-gnupg.svg
    :target: https://badge.fury.io/py/tiny-gnupg

.. image:: https://img.shields.io/github/license/rmlibre/tiny_gnupg
    :alt: GitHub

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://img.shields.io/badge/code%20style-black-000000.svg

.. image:: https://raw.githubusercontent.com/rmlibre/tiny_gnupg/master/tests/coverage.svg?sanitize=true
    :target: https://raw.githubusercontent.com/rmlibre/tiny_gnupg/master/tests/coverage.svg?sanitize=true

.. image:: https://github.com/rmlibre/tiny_gnupg/workflows/Python%20package/badge.svg
    :target: https://github.com/rmlibre/tiny_gnupg/workflows/Python%20package/badge.svg



Install
-------

.. code:: shell

    sudo apt-get install tor torsocks gnupg2
    pip install --user --upgrade tiny_gnupg




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

    # If a command would invoke the need for a passphrase, the
    # with_passphrase kwarg should be set to True ->
    gpg.command(*options, with_passphase=True)

    # The passphrase then needs to be the first arg passed to
    # encode_inputs ->
    gpg.encode_inputs(passphrase, *other_inputs)


    # The list of keys in the package's environment can be accessed
    # from the list_keys() method, which returns a dict ->
    gpg.list_keys()
    # >>> {fingerprint: email_address, ...}

    # Or retrieve a specific key where a searchable portion of its uid
    # information is known, like an email address or fingerprint ->
    gpg.list_keys("username@user.net")
    # >>> {"EE36F0584971280730D76CEC94A470B77ABA6E81": "username@user.net"}

    # The raw output from the --list-keys gpg option can also be
    # accessed ->
    output = gpg.raw_list_keys()


    # Let's try encrypting a message to Alice, whose public key is
    # stored on keys.openpgp.org/.

    # First, we'll import Alice's key from the keyserver (This requires
    # a tor system installation. Or an open tor browser, and the tor_port
    # attribute set to 9150) ->
    from tiny_gnupg import run

    run(gpg.network_import(uid="alice@email.domain"))

    # Then encrypt a message with Alice's key and sign it ->
    msg = "So, what's the plan this Sunday, Alice?"
    encrypted_message = gpg.encrypt(message=msg, uid="alice@email.domain", sign=True)

    # The process of encrypting a message to a peer whose public key
    # might not be in the local package keyring is conveniently available
    # in a single method. It automatically searches for the recipient's
    # key on the keyserver so it can be used to encrypt the message ->
    run(gpg.auto_encrypt(msg, "alice@email.domain"))  # Signing is automatic


    # We could directly send a copy of our key to Alice, or upload it to
    # the keyserver. Alice will need a copy so the signature on the
    # message can be verified. So let's upload it to the keyserver ->
    run(gpg.network_export(uid=gpg.fingerprint))

    # Alice could now import our key (after we do an email verification
    # with the keyserver) ->
    run(gpg.network_import("username@user.net"))

    # Then Alice can simply receive the encrypted message and decrypt it ->
    decrypted_msg = gpg.decrypt(encrypted_message)

    # The process of decrypting a encrypted & signed message from a peer
    # whose public key might not be in the local package keyring is
    # conveniently available in a single method. It automatically determines
    # the signing key fingerprint, and searches for it on the keyserver
    # to verify the signature ->
    decrypted_msg = run(gpg.auto_decrypt(encrypted_message))



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
    from tiny_gnupg import GnuPG, run


    async def read_url(url):
        client = GnuPG()
        async with client.network_get(url) as response:
            return await response.text()


    # Now we can read webpages with GET requests ->
    page_html = run(read_url("https://keys.openpgp.org/"))

    # Let's try onionland ->
    url = "http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion/"
    onion_page_html = run(read_url(url))

    # Check your ip address for fun ->
    ip_addr = run(read_url("https://icanhazip.com/"))

    # There's a convenience function built into the class that
    # basically mimics read_url() ->
    ip_addr = run(GnuPG().get("https://icanhazip.com/"))


    # POST requests can also be sent with the network_post() method.
    # Let's use a POST request to send the keyserver a new key we
    # create ->
    async def post_data(gpg, url, payload=""):
        async with gpg.network_post(url, json=payload) as response:
            return await response.text()


    gpg = GnuPG(
        username="username",
        email="username@user.net",
        passphrase="test_user_passphrase",
    )
    gpg.gen_key()
    url = gpg.keyserver_export_api
    payload = {"keytext": gpg.text_export(uid=gpg.fingerprint)}

    api_token_json = run(post_data(gpg, url, payload))

    # There's also a convenience function built into the class that
    # mimics post_data() ->
    api_token_json = run(gpg.post(url, json=payload))

    # And there we have it, it's super simple. And these requests have
    # the added benefit of being completely routed through tor. The
    # keyserver here also has a v3 onion address which we use to query,
    # upload, and import keys. This provides a nice, default layer of
    # privacy to our communication needs. Have fun little niblets!


These networking tools work off instances of aiohttp.ClientSession. To learn more about how to use their POST and GET requests, you can read the docs here_.

.. _here: https://docs.aiohttp.org/en/stable/client_advanced.html#client-session




About Torification
------------------

.. code:: python

    # A user can make sure that any connections gnupg makes with the
    # network are always run through tor by setting torify=True ->
    username = "username"
    email = "username@user.net"
    passphrase = "test_user_passphrase"
    gpg = GnuPG(username, email, passphrase, torify=True)

    # This is helpful because there are gnupg settings which cause
    # certain commands to do automatic connections to the web. For
    # instance, when encrypting, gnupg may be set to automatically
    # search for the recipient's key on a keyserver if it's not in the
    # local keyring. tiny_gnupg doesn't use gnupg's networking
    # interface, and ensures tor connections through the aiohttp_socks
    # library. So, if gnupg makes these kinds of silent connections,
    # it can inadvertently reveal a user's ip.


Using torify requires a tor installation on the user system. If it's
running Debian/Ubuntu then this guide_ could be helpful.

.. _guide: https://2019.www.torproject.org/docs/debian.html.en




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
    signed_data = gpg.sign(target="maybe a hash of a file?")

    # Or sign a key in the package's keyring ->
    gpg.sign("alice@email.domain", key=True)

    # And verify data as well ->
    gpg.verify(message=signed_data)  # throws if invalid

    # Importing key files is also a thing ->
    path_to_file = "/home/user/keyfiles/"
    run(gpg.file_import(path=path_to_file + "alices_key.asc"))

    # As well as exporting public keys ->
    run(gpg.file_export(path=path_to_file, uid=gpg.email))

    # And secret keys, but really, keep those safe! ->
    run(gpg.file_export(path=path_to_file, uid=gpg.email, secret=True))

    # The keys don't have to be exported to a file. Instead they can
    # be exported as strings ->
    my_key = gpg.text_export(uid=gpg.fingerprint)

    # So can secret keys (Be careful!) ->
    my_secret_key = gpg.text_export(gpg.fingerprint, secret=True)

    # And they can just as easily be imported from strings ->
    gpg.text_import(key=my_key)




Retiring Keys
-------------

After a user no longer considers a key useful, or wants to dissociate from the key, then they have some options:

.. code:: python

    from tiny_gnupg import GnuPG, run

    gpg = GnuPG(
        username="username",
        email="username@user.net",
        passphrase="test_user_passphrase",
    )

    # They can revoke their key then distribute it publicly (somehow)
    # (the keyserver can't currently handle key revocations) ->
    gpg.revoke(gpg.fingerprint)
    key = gpg.text_export(gpg.fingerprint)  # <--  Distribute this!

    # And/or they can delete the key from the package keyring like
    # this ->
    gpg.delete(uid="username@user.net")


.. _key revocations: https://gitlab.com/hagrid-keyserver/hagrid/issues/137
