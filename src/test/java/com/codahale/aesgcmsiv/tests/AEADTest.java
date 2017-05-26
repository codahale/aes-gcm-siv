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
import com.google.common.io.Resources;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import okio.ByteString;
import org.junit.jupiter.api.Test;
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

  @Test
  void testVectors() throws Exception {
    final URL file = Resources.getResource("test-vectors.csv");
    final List<String[]> vectors = Resources.readLines(file, StandardCharsets.UTF_8)
                                            .stream()
                                            .skip(1)
                                            .map(l -> l.split(","))
                                            .collect(Collectors.toList());
    for (String[] vector : vectors) {
      final ByteString key = ByteString.decodeHex(vector[0]);
      final ByteString nonce = ByteString.decodeHex(vector[1]);
      final ByteString plaintext = ByteString.decodeHex(vector[2]);
      final ByteString data = ByteString.decodeHex(vector[3]);
      final ByteString ciphertext = ByteString.decodeHex(vector[4]);

      final AEAD aead = new AEAD(key);
      final ByteString c = aead.seal(nonce, plaintext, data);
      assertEquals(ciphertext, c);

      final Optional<ByteString> p = aead.open(nonce, c, data);
      assertTrue(p.isPresent());
      assertEquals(plaintext, p.get());
    }
  }

  @Test
  void exampleRoundTrip() throws Exception {
    final ByteString key = ByteString.decodeHex("ee8e1ed9ff2540ae8f2ba9f50bc2f27c");
    final ByteString nonce = ByteString.decodeHex("752abad3e0afb5f434dc4310");
    final ByteString plaintext = ByteString.encodeUtf8("Hello world");
    final ByteString data = ByteString.encodeUtf8("example");

    final AEAD aead = new AEAD(key);
    final ByteString ciphertext = aead.seal(nonce, plaintext, data);

    assertEquals(ByteString.decodeHex("5d349ead175ef6b1def6fd4fbcdeb7e4793f4a1d7e4faa70100af1"),
        ciphertext);

    final Optional<ByteString> p = aead.open(nonce, ciphertext, data);
    assertTrue(p.isPresent());
    assertEquals(plaintext, p.get());
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