# p_fed

A utility for encrypting files using a password and decrypting files encrypted with it.
Encryption is done using pyca/cryptography library.
Algorithms used are:

- AES256 - for encryption
- Scrypt - as kind of a hash function to store passwords safely inside the files
- PBKDF2HMAC - for key derivation

I would still consider p_fed work in progress.
**Be careful!**

## Warning

If you forget your password, the file might be irrecoverably lost.
Therefore I can not assure you that you won't lose any data.

**So be cautious when using this program!**

## About

I made this for myself initially and decided to put it here for people that might want to use it.

Any changes are welcome if they:

1. Improve security
2. Improve accessibility
3. Make code more compliant with the standards

## Security

I assumed security was "_good enough for me_" but if you are planning on using this for any serious projects and don't know anything about cryptography, **DON'T USE THIS!!** For anyone that understands cryptography, you probably know more than me. So any help from you will seriously help.

## Things you can help with

1. I couldn't quite figure out how to store the salt for passwords. Currently it's a set string of bytes located in p_fed.py.
2. The printed text for verbosity levels doesn't feel quite right.
3. Probably many more, if you find anything
