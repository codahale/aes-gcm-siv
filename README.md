# AES-GCM-SIV

[![Build Status](https://secure.travis-ci.org/codahale/aes-gcm-siv.svg)](http://travis-ci.org/codahale/aes-gcm-siv)

A Java implementation of [AES-GCM-SIV](https://eprint.iacr.org/2017/168) 
([draft-irtf-cfrg-gcmsiv-04](https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-04)), a
nonce misuse-resistant Authenticated Encryption And Data (AEAD) algorithm.

## Is it ready

No, AES-GCM-SIV is still in draft form and hasn't yet been standardized. This library implements the
algorithm described in
[draft-irtf-cfrg-gcmsiv-04](https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-04).

## Is it fast

Well, no. AES-GCM-SIV's performance is largely dependent on hardware support for AES and GCM, but
the Java Virtual Machine intrinsics for AES-NI and GCM are not available for general use. Java 8
added AES-NI support, but only for AES-CBC, and Java 9 will improve GCM performance via `pclmulqdq`
intrinsics, but only for AES-GCM. Still, things are plenty fast — encrypting a 1KiB message takes
about 40-50µs on my laptop.

## Add to your project

```xml
<dependency>
  <groupId>com.codahale</groupId>
  <artifactId>aes-gcm-siv</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Use the thing

```java
import com.codahale.aesgcmsiv.AEAD;
import okio.ByteString;
import java.util.Optional;

class Example {
  void doIt() {
    final ByteString key = ByteString.decodeHex("ee8e1ed9ff2540ae8f2ba9f50bc2f27c");
    final ByteString nonce = ByteString.decodeHex("752abad3e0afb5f434dc4310");
    final ByteString plaintext = ByteString.encodeUtf8("Hello world");
    final ByteString data = ByteString.encodeUtf8("example");
   
    final AEAD aead = new AEAD(key);
    final ByteString ciphertext = aead.seal(nonce, plaintext, data);
    final Optional<ByteString> result = aead.open(nonce, ciphertext, data);

    System.out.println(result);
  } 
}
```

## License

Copyright © 2017 Coda Hale

Distributed under the Apache License 2.0.
