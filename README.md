# RSAPublicKey
Using RSA publickey's modulus and exponent to create SecKeyRef and do encrytion and decrytion.

This takes me several days digging in stackoverflow and other websites and finally it works on iOS9.

Method:

1. Use BasicEncodingRules to create a RSA public key object, which can be used for SecKeyEncrypt function to do encrypt.
2. A workaround fix for BasicEncodingRules against iOS9 can be found in RSAPubKey.m, line 53.
3. RSA decryption is using kSecPaddingNone mode, and handle the padding myself simply after SecKeyDecrypt. This is tested against Java PKCS1 Padding, not tested for C# or other languages.


