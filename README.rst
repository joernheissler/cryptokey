CryptoKey
=========

Python (>= 3.5) library for pluggable asymmetric low-level encryption.

Goals
-----

- Provide a pluggable API for asymmetric keys in pure python.
- Plays nicely with asynchronous frameworks.
- Theoretical support for all kinds of cryptographic backends, such as openssl,
  your favourite HSM or smartcard, cloud HSMs, your own ECC implementation (don't!), etc.
- No dependencies on any libraries.
