# JCryptoBox

JCryptoBox is a simple cryptography facade inspired by NaCl and libsodium that uses slightly more conservative cryptography standards (NIST FIPS 140).
Cryptographic APIs are enabled via boxes.
Secret key cryptography is exposed via `SecretBoxFactory`.
Public key cryptography is exposed for mutual authentication via `BoxFactory` and for anonymous senders via `SealedBoxFactory`.
