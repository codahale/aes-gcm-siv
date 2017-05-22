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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codahale.aesgcmsiv.AEAD;
import com.google.common.io.Resources;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import okio.ByteString;
import org.junit.jupiter.api.Test;

class AEADTest {

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
      final ByteString nonce = ByteString.decodeHex(vector[1].substring(0, 24));
      final ByteString plaintext = ByteString.decodeHex(vector[2]);
      final ByteString data = ByteString.decodeHex(vector[3]);
      final ByteString ciphertext = ByteString.decodeHex(vector[4]);

      final AEAD aead = new AEAD(key.toByteArray());
      final byte[] c = aead.seal(nonce.toByteArray(), plaintext.toByteArray(), data.toByteArray());
      assertEquals(ciphertext, ByteString.of(c));

      final Optional<byte[]> p = aead.open(nonce.toByteArray(), c, data.toByteArray());
      assertTrue(p.isPresent());
      assertEquals(plaintext, ByteString.of(p.get()));
    }
  }

  @Test
  void exampleRoundTrip() throws Exception {
    final byte[] key = ByteString.decodeHex("ee8e1ed9ff2540ae8f2ba9f50bc2f27c").toByteArray();
    final byte[] nonce = ByteString.decodeHex("752abad3e0afb5f434dc4310").toByteArray();
    final byte[] plaintext = ByteString.encodeUtf8("Hello world").toByteArray();
    final byte[] data = ByteString.encodeUtf8("example").toByteArray();

    final AEAD aead = new AEAD(key);
    final byte[] ciphertext = aead.seal(nonce, plaintext, data);

    assertEquals(ByteString.decodeHex("5d349ead175ef6b1def6fd4fbcdeb7e4793f4a1d7e4faa70100af1"),
        ByteString.of(ciphertext));

    final Optional<byte[]> end = aead.open(nonce, ciphertext, data);

    assertArrayEquals(plaintext, end.orElseThrow(NullPointerException::new));
  }
}