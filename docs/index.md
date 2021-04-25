# JCryptoBox

JCryptoBox is a simple cryptography facade inspired by NaCl and libsodium that uses slightly more conservative cryptography standards (NIST FIPS 140).
Cryptographic APIs are exposed via `Box` and `SealedBox`.
By default, boxes provide 128-bit security.
