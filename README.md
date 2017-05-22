# AES-GCM-SIV

[![Build Status](https://secure.travis-ci.org/codahale/aes-gcm-siv.svg)](http://travis-ci.org/codahale/aes-gcm-siv)

A Java implementation of [AES-GCM-SIV](https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-04), a
nonce misuse-resistant Authenticated Encryption And Data (AEAD) algorithm.

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

## Is it ready

No, AES-GCM-SIV is still in draft form and hasn't yet been standardized.

## License

Copyright © 2017 Coda Hale

Distributed under the Apache License 2.0.
