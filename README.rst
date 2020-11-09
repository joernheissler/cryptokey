CryptoKey
=========

Python (>= 3.8) library for asymmetric cryptography with algorithms such as RSA and ECC.

Various backends implement wrappers around other crypto libraries (such as https://cryptography.io/)
and makes them available using a unified API. The actual cryptographic operations are carried out
by those backend libraries.

No hard dependencies on any non-python libraries such as OpenSSL exist.

CryptoKey is meant to be used by other libraries that need to carry out cryptographic
operations. That could e.g. be an ACME client, TrustedTimeStamp service or an SSH client.

Users can implement their own backends to utilise their favourite HSM or smartcard,
cloud HSMs or their own ECC implementation (don't!), etc.

CryptoKey can thus be seen as a python alternative to PKCS#11.

There are high-level interfaces such as `key.sign(msg)` which just do the right thing,
and low-level interfaces such as `rsakey.sign_int` to calculate `s = m ** d % n` which,
if used incorrectly, opens up security holes.

Implementations for padding schemes such as PSS are given. They can be used for low-level
plumbing like extracting the salt from a PSS signature or creating a PSS signature with a
specific salt.

One stated goal is to provide interfaces for unsafe operations too.
If you want to shoot yourself in the foot, here's the tool to do it!

Backends
========
* `cryptography <https://github.com/joernheissler/cryptokey-cryptography>`__ which uses
  https://cryptography.io/ and thus OpenSSL. Recommended for most users.

* `hashlib <https://github.com/joernheissler/cryptokey-hashlib>`__ implements hash operations using
  https://docs.python.org/3/library/hashlib.html.

* `oscrypto <https://github.com/joernheissler/cryptokey-oscrypto>`__ uses https://github.com/wbond/asn1crypto
  which in turn uses OS provided crypto libraries without requiring a C compiler.

* `partial <https://github.com/joernheissler/cryptokey-partial>`__ provides partial implementations of
  many functions and can be used to build another backend on top of it.

* `textboox <https://github.com/joernheissler/cryptokey-textbook>`__ is a complete but deliberately insecure
  backend that implements all crypto operations without using other libraries. Can be used for doing crypto
  related homework or for learning how to implement timing attacks.


Examples
========

Sign a message
--------------

.. code-block:: python

   from asyncio import run
   from cryptography.hazmat.primitives import serialization
   from cryptokey.backend.cryptography import backend
   from cryptokey.backend.cryptography.rsa import RsaPrivateKey

   # Load a private key using normal cryptography.io operations.
   with open('private.key', 'rb') as fp:
      cryptography_key = serialization.load_pem_private_key(
         fp.read(),
         password=None,
         backend=backend,
      )

   # Create wrapper
   key = RsaPrivateKey(cryptography_key)

   # Sign a message. By default, PSS and SHA2_256 are used. The
   # signature object also contains the parameters that were used.
   sig = run(key.sign(b'Hello, World!'))

   # Write signature to a file.
   with open('hello.sig', 'wb') as fp:
      fp.write(sig.value)

Verifying the signature using openssl
-------------------------------------

.. code-block:: sh

   echo -n 'Hello, World!' | openssl sha256 -binary | openssl pkeyutl \
        -verify -inkey private.key -sigfile hello.sig                 \
        -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss

Solving homework
----------------

.. code-block:: python

   from asyncio import run
   from cryptokey.backend.textbook.rsa import TextbookRsaPrivateKey

   key = TextbookRsaPrivateKey(public_exponent=7, primes=(17, 31))
   print(f'Private exponent: {key.private_exponent}')
   print(f'Signature for M=2: {run(key.sign_int(2)).int_value}')

Security
========
This library is supposed to be just as (in)secure as the used backend.
If in doubt, use the `cryptography` backend, which builds upon OpenSSL.
