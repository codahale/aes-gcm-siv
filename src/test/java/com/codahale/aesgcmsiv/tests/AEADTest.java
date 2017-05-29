/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.codahale.aesgcmsiv.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.quicktheories.quicktheories.QuickTheory.qt;

import com.codahale.aesgcmsiv.AEAD;
import java.util.Optional;
import javax.annotation.Nullable;
import okio.ByteString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.quicktheories.quicktheories.core.Source;

class AEADTest {

  private static Source<ByteString> byteStrings(int minSize, int maxSize) {
    return Source.of((prng, step) -> {
      final byte[] bytes = new byte[prng.nextInt(minSize, maxSize)];
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) prng.nextInt(0, 255);
      }
      return ByteString.of(bytes);
    });
  }

  @ParameterizedTest
  @CsvFileSource(resources = {
      "/8_Worked_example.csv",
      // all test vectors from Appendix C
      "/C1_AEAD_AES_128_GCM_SIV.csv",
      "/C2_AEAD_AES_256_GCM_SIV.csv",
      "/C3_Counter_wrap_tests.csv"
  })
  void matchTestVectors(String k, String n, @Nullable String p, @Nullable String d, String c) {
    final ByteString key = ByteString.decodeHex(k);
    final ByteString nonce = ByteString.decodeHex(n);
    final ByteString plaintext = p == null ? ByteString.EMPTY : ByteString.decodeHex(p);
    final ByteString data = d == null ? ByteString.EMPTY : ByteString.decodeHex(d);
    final ByteString ciphertext = ByteString.decodeHex(c);

    final AEAD aead = new AEAD(key);
    final ByteString c2 = aead.seal(nonce, plaintext, data);
    assertEquals(ciphertext, c2);

    final Optional<ByteString> p2 = aead.open(nonce, c2, data);
    assertTrue(p2.isPresent());
    assertEquals(plaintext, p2.get());
  }

  @Test
  void roundTrip() throws Exception {
    qt().forAll(byteStrings(16, 16), byteStrings(12, 12), byteStrings(0, 1024),
        byteStrings(0, 1024))
        .check((key, nonce, plaintext, data) -> {
          final AEAD aead = new AEAD(key);
          final ByteString ciphertext = aead.seal(nonce, plaintext, data);
          final Optional<ByteString> message = aead.open(nonce, ciphertext, data);

          return message.isPresent() && plaintext.equals(message.get());
        });
  }

  @Test
  void simpleRoundTrip() throws Exception {
    qt().forAll(byteStrings(16, 16), byteStrings(0, 1024), byteStrings(0, 1024))
        .check((key, plaintext, data) -> {
          final AEAD aead = new AEAD(key);
          final ByteString ciphertext = aead.seal(plaintext, data);
          final Optional<ByteString> message = aead.open(ciphertext, data);

          return message.isPresent() && plaintext.equals(message.get());
        });
  }
}