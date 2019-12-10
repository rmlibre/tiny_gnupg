tiny_gnupg - A small-as-possible solution for handling GnuPG ECC keys.
======================================================================
This project has evolved quickly with the achievement of fully automated,
programatic access to gpg's functionality. It is now in unstable beta. 
The aim is for a small, simple & intuitive wrapper for creating and using 
GnuPG's Ed-25519 curve keys. We are in favor of reducing code size and 
complexity with strong and bias defaults over flexibility in the api. 
Contributions welcome.

This package is only seeking to be compatible with linux systems.


Usage Example
-------------

.. code:: python

    from tiny_gnupg import GnuPG

    username = "username"
    email = "username@user.net"
    passphrase = "test_user_passphrase"
    gpg = GnuPG(username, email, passphrase)

    # This will generate a new combined encryption ed25519 ECC key and
    # signing/certifying ed25519 ECC key.
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
    # We can import Alice's key from the keyserver (This requires 
    # a tor system installation. Or an open tor browser, and the tor_port
    # attribute set to 9150) ->
    import asyncio

    run = asyncio.get_event_loop().run_until_complete
    run(gpg.network_import("alice@email.domain"))

    # Then encrypt a message with Alice's key and sign it ->    
    msg = "So, what's the plan this Sunday, Alice?"
    encrypted_message = gpg.encrypt(msg, "alice@email.domain") # also signs the message

    # We could directly send a copy of our key to Alice. Or, upload the key
    # to the keyserver. Alice will need a copy of the key so the signature 
    # on the message can be verified ->
    run(gpg.network_export(gpg.fingerprint))

    # Then Alice can simply receive the encrypted message and decrypt it ->
    decrypted_msg = gpg.decrypt(encrypted_message)

On most systems, because of a bug in GnuPG_, email verification will be necessary for others to import the keys this package creates from the keyserver. We will replace the gpg2 executable as soon as a patch becomes available.
If the gpg2 executable doesn't work on your system, replace it with a copy of the executable found on your system. The executable can be found at package_path/gpghome/gpg2. This path is also available from a class instance under the instance.executable attribute.
    
.. _GnuPG: https://dev.gnupg.org/T4393



Extra Example
-------------

.. code:: python

    #
    # Since we use SOCKSv5 networking over tor, and the aiohttp + aiohttp_socks 
    # libraries, the tor networking interface is also available to users. These
    # allow arbitrary POST and GET requests to clearnet, or onionland,
    # websites ->
    #
    import asyncio
    from tiny_gnupg import GnuPG


    async def read_url(url):
        client = GnuPG()
        async with client.network_get(url) as response:
            return await response.text()


    run = asyncio.get_event_loop().run_until_complete

    # Now we can read webpages with get requests ->
    page_html = run(read_url("https://keys.openpgp.org/"))

    # Let's try onionland ->
    url = "http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion/"
    onion_page_html = run(read_url(url))

    # Check your ip address for fun ->
    ip_addr = run(read_url("https://icanhazip.com/"))

    # POST requests can also be sent with the network_post() method.
    # These work off instances of aiohttp.ClientSession. To learn more
    # about how to use their post and get requests, you can read the docs
    # here: 
    # https://docs.aiohttp.org/en/stable/client_advanced.html#client-session