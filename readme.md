# p_fed

<p align="center">
<b>THIS IS NOT WRITTEN BY AN EXPERT, EXPECT SECURITY ISSUES!</b> But if you are, please consider helping.
</p>

A utility for encrypting files using a password and decrypting files encrypted with it.
Encryption is done using [pyca/cryptography](https://github.com/pyca/cryptography) library.

## About dev branch

New features and fixes are done in here first. Do not use this branch except for development.
Might not work sometimes.

## Current state of dev

Does not work because decryption is not fully implemented yet.
But most of the encryption code is done.
Now program is compatible with other modes of operation or encryption algorithms.

## Warning

If you forget your password, the file might be irrecoverably lost.
Therefore I can not assure you that you won't lose any data.

**So be cautious when using this program!**

## About

I made this for myself initially and decided to put it here for people that might want to use it.
**I'm not an expert in cryptography** keep that in mind.

Any changes are welcome if they:

1. Improve security,
2. Make code more compliant with PEP8 and maybe PEP484,
3. Make package structure more usable and readable

## Security

I assumed security was "_good enough for me_" but if you are planning on using this for any serious projects and don't know anything about cryptography, **DON'T USE THIS!!** For anyone that understands cryptography, you probably know more than me. So any help from you will seriously be appreciated.

## Things you can help with

1. No other encryption algorithm is supported except AES-256, it would be better if it did.
2. Similarly, no other mode of operation is supported other than CBC, it might be good enough but, different modes of operation for different use cases would be better.
3. Currently using SHA3-512 for PBKDF2HMAC hash algorithm to still have security even if there are serious vulnerabilities found for SHA256 at some point. But SHA3 might be too slow for some, if someone can verify the security with blake2b or find another option, that would be appreciated.
4. The printed text for verbosity levels doesn't feel quite right.
5. Probably many more, if you find anything tell me about it. And if you can, try fixing it yourself then make a pull request.
