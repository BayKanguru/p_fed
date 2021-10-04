# p_fed

<p align="center">
<b>THIS IS NOT WRITTEN BY AN EXPERT, EXPECT SECURITY ISSUES!</b> But if you are, please consider helping.<br>
<b>I have seen it delete contents of files so it is not ready for use.</b>
</p>

A utility for encrypting files using a password and decrypting files encrypted with it.
Encryption is done using [pyca/cryptography](https://github.com/pyca/cryptography) library.

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

1. Might delete contents of files on errors? Seen that happen a few times but there were bigger problems then.
1. There are no cl arguments for using different encryption algorithms or modes of operation.
1. Currently using SHA3-512 for PBKDF2HMAC hash algorithm to still have security even if there are serious vulnerabilities found for SHA256 at some point. But SHA3 might be too slow for some, if someone can verify the security with blake2b or find another option, that would be appreciated.
1. Probably many more, if you find anything tell me about it. And if you can, try fixing it yourself then make a pull request.
