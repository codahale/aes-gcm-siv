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
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;
import okio.ByteString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ObjectArrayArguments;
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

  @SuppressWarnings("unused")
  static Stream<Arguments> testVectors() throws IOException {
    final URL file = Resources.getResource("test-vectors.csv");
    return Resources.readLines(file, StandardCharsets.UTF_8)
                    .stream()
                    .skip(1)
                    .map(l -> ObjectArrayArguments.create(Arrays.stream(l.split(","))
                                                                .map(ByteString::decodeHex)
                                                                .toArray()));
  }

  @ParameterizedTest
  @MethodSource(names = "testVectors")
  void matchTestVectors(ByteString k, ByteString n, ByteString p, ByteString d, ByteString c) {
    final AEAD aead = new AEAD(k);
    final ByteString c2 = aead.seal(n, p, d);
    assertEquals(c, c2);

    final Optional<ByteString> p2 = aead.open(n, c2, d);
    assertTrue(p2.isPresent());
    assertEquals(p, p2.get());
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