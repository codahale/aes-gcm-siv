# AES-GCM-SIV

[![Build Status](https://secure.travis-ci.org/codahale/aes-gcm-siv.svg)](http://travis-ci.org/codahale/aes-gcm-siv)

A Java implementation of [AES-GCM-SIV](https://eprint.iacr.org/2017/168) 
([draft-irtf-cfrg-gcmsiv-05](https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-05)), a
nonce-misuse resistant Authenticated Encryption And Data (AEAD) algorithm.

## Is it ready

No, AES-GCM-SIV is still in draft form and hasn't yet been standardized. This library implements the
algorithm described in
[draft-irtf-cfrg-gcmsiv-05](https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-05).

## Is it fast

It's plenty fast. AES-GCM-SIV's performance is largely dependent on hardware support for AES and
GCM. Java 8 added AES-NI support, but only for AES-CBC, and Java 9 will improve GCM performance via
`pclmulqdq` intrinsics, but only for AES-GCM. Still, things are plenty fast — encrypting a 1KiB
message on my laptop is only slightly slower than AES-GCM:

```
Benchmark               Mode  Cnt   Score   Error  Units
Benchmarks.aes_GCM      avgt  200  22.435 ± 0.122  us/op
Benchmarks.aes_GCM_SIV  avgt  200  24.824 ± 0.530  us/op
```

## Ok then why's it good

AES-GCM-SIV is a nonce-misuse resistant AEAD, which means it doesn't fail catastrophically if a
nonce gets re-used. This is a concern for large systems which involve operations with a single key:

> Since a central allocation system for nonces is not operationally viable, random selection of
nonces is the only possibility. AES-GCM’s limit of 2^32 random nonces (per key) suggests that, even
if the system rotated these secret keys daily, it could not issue more than about 50K tokens per
second. However, in order to process DDoS attacks the system may need to sustain issuance of several
hundred million per second.

Unlike AES-GCM or ChaChaPoly1305, AES-GCM-SIV can tolerate _some_ duplicate nonces, but it still has
limits:

> When discussing this work, we found a widespread misunderstanding of the term “nonce-misuse
resistant”. Many people appear to expect the security of a nonce-misuse resistant scheme to be
completely unaffected by the number of times that a nonce is reused. Thus, while it is a convenient
shorthand to distinguish schemes that tolerate repeated nonces (e.g., AES-GCM-SIV) from those that
do not (e.g., AES-GCM and ChaCha20-Poly1305), nonce-misuse resistance is not necessarily a “binary”
property. In particular, it is not binary for the case of AES-GCM-SIV, and as we have shown the
security bounds of AES-GCM-SIV change as the number of repeated nonces varies.
>
> As such, it is important to understand what security is actually guaranteed by nonce-misuse
resistance. First and foremost, nonce-misuse resistant schemes reveal when the same plaintext is
encrypted using the same nonce, and this is well understood. Due to this, some have concluded that
if an application guarantees unique plaintexts, then the same nonce can be safely reused in every
encryption. Although this is true in some sense, it is also true that the security bounds can be
degraded, as we have shown in this paper. Thus, it is not recommended to purposefully use
AES-GCM-SIV with the same nonce (unless the number of encryptions is small enough so that the
quadratic bound is small). We stress that if the same nonce is used always, then AES-GCM-SIV is no
worse than previous schemes; however, AES-GCM-SIV can achieve far better bounds and it is worth
taking advantage of this. 
> 
> We believe that AES-GCM-SIV is well suited to applications where independent servers need to work
with the same key, and where nonce repetition is a real threat. In such cases, it is not possible to
enjoy the better bounds available for encryption schemes that utilize state to ensure unique nonces
in every encryption.

(quotes from ["AES-GCM-SIV: Specification and Analysis"](https://eprint.iacr.org/2017/168))

## Add to your project

```xml
<dependency>
  <groupId>com.codahale</groupId>
  <artifactId>aes-gcm-siv</artifactId>
  <version>0.3.0</version>
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
    final AEAD aead = new AEAD(key);
    
    final ByteString plaintext = ByteString.encodeUtf8("Hello world");
    final ByteString data = ByteString.encodeUtf8("example");
   
    // automatically generates a nonce
    final ByteString ciphertext = aead.seal(plaintext, data);
    
    // automatically parses the nonce from the ciphertext
    final Optional<ByteString> result = aead.open(ciphertext, data);

    System.out.println(result);
  } 
}
```

`AEAD` also has versions of `seal` and `open` which support pre-generated nonces.

## License

Copyright © 2017 Coda Hale

Distributed under the Apache License 2.0.
