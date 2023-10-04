# What is cryptography?

Cryptography is a collection of techniques for:

-   concealing data transmitted over insecure channels
-   validating message integrity and authenticity

# Some cryptographic terms

plaintext – a message or other data in readable form

ciphertext – a message concealed for transmission or storage

encryption – transforming plaintext into ciphertext

decryption – transforming ciphertext back into plaintext

key – an input to an encryption or decryption algorithm that determines the specific transformation applied

hash – the output of an algorithm that produces a fixed N-bit output from any input of any size

entropy – the number of possible states of a system, or the number of bits in the shortest possible description of a quantity of data. This may be less than the size of the data if it is highly redundant.

# Basic cryptographic algorithms

## Symmetric ciphers

A symmetric cipher uses the same key for encryption and decryption. In semi-mathematical terms,

encryption: ciphertext = E(plaintext, key)

decryption: plaintext = D(ciphertext, key)

Two parties that want to communicate via encryption must agree on a particular key to use, and sharing and protecting that key is often the most difficult part of protecting encryption security.

The number of possible keys should be large enough that a third party can’t feasibly try all of the keys (“brute-forcing”) to see if one of them decrypts a message.

## Block ciphers

A block cipher works on fixed-size units of plaintext to produce (usually) identically-sized units of ciphertext, or vice-versa.

Example block ciphers:

-   DES (the former Data Encryption Standard) with a 64-bit block and 56-bit keys, now obsolete because both the block size and key size are too small and allow for easy brute-forcing)
-   AES (Advanced Encryption Standard, formerly known as Rijndael) with 128-bit blocks and keys of 128, 192, or 256 bits

## Stream ciphers

A stream cipher produces a stream of random bits based on a key that can be combined (usually using XOR) with data for encryption or decryption.

Example stream ciphers:

-   Chacha20
-   RC4 (now considered too weak to use)

## Public-key (or asymmetric) ciphers

A public-key cipher has two complementary keys K1 and K2 such that one can reverse what the other one does, or in symbolic terms:

ciphertext = E(plaintext, K1) **or** E(plaintext, K2)

plaintext = D(ciphertext, K2) **or** D(plaintext, K1)

Unlike a symmetric cipher, where the key must be kept secret between parties at all times, a public-key algorithm allows one (but only one!) of the keys to be revealed in public, making it possible to send encrypted messages without having previously arranged to share a key.

Example public-key algorithms:

-   RSA (from the initials of its creators Rivest, Shamir, Adelman) based on modular arithmetic using large prime numbers and the difficulty of factoring large numbers. At this time 2048-bit primes are considered necessary to create secure RSA keys (factorization of keys based on 512-bit primes has already been demonstrated and 1024-bit keys appear feasible)
-   Elliptic Curve algorithms based on integers and modular arithmetic satisfying an equation of the form y^2 = x^3 + a*x + b. Elliptic curve keys can be much shorter (256-bit EC keys are considered roughly equivalent to 3072-bit RSA keys).

However, public-key algorithms are much (hundreds to thousands) of times slower than symmetric algorithms, making it expensive to send large amounts of data using only public-key encryption. However, public-key algorithms do provide a secure way to transmit symmetric cipher keys.

## Diffie-Hellman key exchange

An algorithm that allows two parties to create a shared secret through a public exchange from which an eavesdropper cannot feasibly infer the secret. Useful for establishing a shared symmetric key for encrypted communication. Diffie-Hellman can be peformed using either modular arithmetic with large prime numbers or with elliptic-curve fields.

Diffie-Hellman is also usually the basis of “forward secrecy”. One method of key exchange possible in SSL/TLS is simply using a public-key algorithm to send a key between a client and a server. However, if the private key of that SSL/TLS certificate is later exposed, someone who monitored and recorded session traffic could decrypt all the keys used in the sessions they recorded. Forward secrecy not only involves setting up unique, random session keys for each communication session, but also using an algorithm like Diffie-Hellman which establishes those keys in a way that is inaccessible to an eavesdropper.

## Hash algorithms

A hash (or cryptographic checksum) reduces input data (of any size) to a fixed-size N-bit value. In particular for cryptographic use a hash has these properties:

-   two different inputs are very unlikely to produce the same hash (“collision”).
-   it should be very difficult to find another input that produces any specified hash value (“preimage”)
-   even a one-bit change in the input should produce a hash that is different in about N/2 bits

Note that because the possible number of inputs to a hash function is much larger than the hash function output, there is always some small probability of collision or of finding a preimage. In the ideal case an N-bit hash has a 2^-(N/2) probability of collision for two randomly-chosen large inputs (look up the “birthday problem” for why it is N/2 and not N), and a 2^-N probability of a random input producing a specified hash value.

Example hash algorithms:

-   MD5 produces a 128-bit hash from its input. It has demonstrated collisions and feasible preimage computation and should not be used.
-   SHA1 produces 160-bit hashes but has at least one demonstrated collision and is also deprecated for cryptographic use (however, it is still used in git because it is still workable as a hash function).
-   SHA-256 produces 256-bit hashes. SHA-224 is basically a SHA-256 hash truncated to 224 bits.
-   Similarly, SHA-512 produces a 512-bit hash and SHA-384 truncates a SHA-512 hash to 384 bits.

## Cryptographic random number generators

Many cryptographic methods require producing random numbers (such as for generating unique keys or identifiers). Traditional pseudo-random number generators produce output that can be highly predictable, as well as often starting from known states and having relatively small periods (such as 2^32). A cryptographic random number generator must make it very difficult to determine the prior (or future) state of the generator from its current output, as well as have enough entropy to generate sufficiently large random numbers.

Once the Debian maintainers made a seemingly innocuous patch to the OpenSSL random number generator initialization. The unintended consequence was that it effectively seeded the generator with only about 16 bits of entropy, meaning that in particular ssh-keygen generated only about 2^16 possible 2048-bit SSH host keys when it really should have been capable of generating over 2^2000. Once this was discovered and patched a lot of people had to change their host keys (or risk “man-in-the middle” impersonation attacks).

Finding useful random input to make a cryptographic random number generator truly unpredictable can be difficult. Many systems attempt to collect physically random input (such as timing of disk I/O, network packets, or keyboard input) that is “mixed” into existing random state using a cipher or cryptographic hash.

# Cryptographic Protocols

The algorithms described above are building blocks for methods of secure communication. A particular combination of these basic algorithms applied in a particular way is a cryptographic protocol.

## Cipher modes

The simplest thing you can do with a block cipher is break plaintext up into blocks, then encrypt each block with your chosen key (also called ECB for “Electronic Code Book”, by analogy with codes that simply substituted code words). Unfortunately this leads to a weakness: if you a particular plaintext block is repeated in the input the ciphertext block also repeats in the output. This can easily happen in English text if a phrase just happens to line up with a block the same way more than once.

There are other ways to use block ciphers to avoid this. The simplest is CBC or “Cipher Block Chaining” where the previous ciphertext block is XORed with the current plaintext block before encrypting it. This is reversible by decrypting a ciphertext block, then XORing the previous ciphertext block with that to recover the plaintext. There are other modes like OFB (“Output FeedBack”) that combine ciphertext and plaintext in more complicated but reversible ways so that repeated plaintext blocks won’t result in repeated ciphertext blocks. These modes also often depend on an “initialization vector” which is typically some cryptograpically random value that makes the initial state of the encryption unpredictable to an outside observer.

## Message signing

Someone who has created a public key pair (K1, K2) and published a public key (let’s say that’s K2) can encrypt a message using their private key K1, and anyone can validate that the message came from that sender by decrypting it with the public key K2.

Due to the much higher computational cost of encrypting data with public-key algorithms, usually the signer actually encrypts only a cryptographic hash of the original message. A sender can also send a plaintext message along with a signature created with their private key if the privacy of the message is not important but validating the identity of the sender is.

Message signing is also the basis of SSL/TLS certificate validation. A certificate contains a public key and a signature of that key generated with the private key of a trusted certificate authority. An SSL/TLS client (such as a web browser) can confirm the authenticity of the public key by validating the certificate signature using the public key of the certificate authority that signed it.

An SSL/TLS client can validate the identity of a server by encrypting a large random number with the public key in the server certificate. If the server can decrypt the random number with its private key and return it, the client can assume the server is what it says it is.

“Self-signed” certificates are merely public keys signed with the corresponding private key. This isn’t as trustworthy (assuming you have reasons to trust a certificate authority) but also doesn’t require interaction with a certificate authority. However, ultimately the buck has to stop somewhere and even certificate authority “root certificates” are self-signed.

Rather than the centralized certificate authority model (where certain authorities are trusted to sign certificates) email encryption tools like GPG have a “web of trust” model where someone’s public key can be signed by many other individuals or entities, so that if you trust at least some of those others it gives you greater assurance that a public key is valid and belongs to the indicated person. Without any such signatures, someone could presumably publish a key purporting to be someone else and there’d be no easy way to validate it.

## Secure email

If you want people to be able to send you secure email (such as with PGP, GPG, or S/MIME) you create a public key pair (K1, K2) and publish the public key K2.

Someone who wants to send you mail picks a cipher and generates a unique, random key for that cipher. They encrypt their plaintext message with that cipher and key and encrypt the key with your public key, and send you a message containing the ciphertext, the cipher algorithm they used, and the encrypted cipher key.

You can decrypt the cipher key with your private key, and then decrypt their message from the ciphertext and indicated cipher.

Note that for this model to work everyone who wants to receive encrypted email has to publish a public key.

## SSL/TLS

SSL (Secure Sockets Layer, now deprecated) and TLS (Transport Layer Security) use all of the above cryptographic primitives to secure data sent over a network. As a result the protocol is rather complicated, but in summary does these things:

-   client and server agree on a “cipher suite” to use, which consists of:
    -   a method for key exchange (via the public/private key pair in a certificate or Diffie=Hellman key exchange)
    -   a method for server validation (based on the public-key algorithm used in its certificate)
    -   a symmetric cipher for bulk data encryption
    -   a hash algorithm to use for message authentication, actually an HMAC or “Hashed Message Authentication Code” that hashes a combination of a secret key and the data)
-   establish random shared key for the symmetric cipher and HMAC using the specified key exchange method
-   transmits data using the specified symmetric cipher and HMAC algorithms

# Cryptanalysis

Cryptanalysis is the study of weaknesses in cryptographic algorithms and protocols. In general, good algorithms and protocols have been subjected to lots of public cryptanalysis that has not resulted in attacks that are significantly better than brute-force. It’s a complex topic, and this is a pretty good introduction:

[https://research.checkpoint.com/cryptographic-attacks-a-guide-for-the-perplexed](https://research.checkpoint.com/cryptographic-attacks-a-guide-for-the-perplexed)

# Cryptographic tools

## OpenSSL

Although it’s taken a lot of heat for some of its previous security issues (particularly “Heartbleed”), it’s still the most widely used cryptographic library because of its portability and completeness.

The **openssl** command-line utility also provideas a lot of useful functionality. It can be used to create certificate requests or even to sign certificates, encrypt/decrypt files, transform several kinds of file formats used for cryptographic data, and more.

Of particular use is the **openssl s_client** command which can initiate an SSL/TLS client connection, but more importantly shows a lot of useful debugging data about the protocol negotiation including the certificate and cipher suite properties.

## Gnutls

The GNU Project’s SSL/TLS library, which includes a **gnutls-cli** utility with similar (but less extensive) functionality for SSL/TLS client connections and encryption/decryption.

## Gnupg

Primarily intended for encrypting or decrypting secure mail messages, it also provides some functionality for encrypting or decrypting files and creating or validating signatures.

# General cryptographic advice

## Use established, publicly analyzed algorithms and tools

Schneier’s Law: “Anyone can create an algorithm that they can’t break.”

[https://www.schneier.com/blog/archives/2011/04/schneiers_law.html](https://www.schneier.com/blog/archives/2011/04/schneiers_law.html)

Resist the urge to create and use your own cryptographic algorithms and protocols. Cryptography is hard and even expert cryptographers have created methods that, once exposed to public analysis, have turned out to be easy to break.

## Zealously protect keys and credentials

Often the easiest way to break a cryptographic system is to find the keys being used. This may be easier than you think. What if you left that certificate private key in a publicly-readable file? What if it’s copied into backups that are available to other untrusted users? Think carefully about how you handle and store that kind of sensitive material.